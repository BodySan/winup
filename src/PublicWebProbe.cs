using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;

namespace WinUp {
    internal static class PublicWebProbe {
        internal static bool IsPublic(IPAddress address){
            if(address.IsIPv4MappedToIPv6)return IsPublic(address.MapToIPv4());
            byte[] b=address.GetAddressBytes();
            if(b.Length==4){
                int a=b[0],s=b[1];
                return !(a==0||a==10||a==127||a>=224||a==100&&s>=64&&s<=127||a==169&&s==254||
                    a==172&&s>=16&&s<=31||a==192&&(s==168||s==0||s==88&&b[2]==99)||
                    a==198&&(s==18||s==19||s==51&&b[2]==100)||a==203&&s==0&&b[2]==113);
            }
            // Globally routable unicast only. Exclude special protocol blocks,
            // documentation and transition mechanisms with embedded IPv4.
            return b.Length==16&&(b[0]&0xe0)==0x20&&
                !(b[0]==0x20&&b[1]==0x01&&(b[2]<2||b[2]==0x0d&&b[3]==0xb8))&&
                !(b[0]==0x20&&b[1]==0x02)&&address.ScopeId==0;
        }
        internal static bool PublicSet(IPAddress[] addresses){return addresses!=null&&addresses.Length>0&&addresses.Length<=32&&addresses.All(IsPublic);}
        static int Remaining(Stopwatch clock){int left=7000-(int)clock.ElapsedMilliseconds;if(left<=0)throw new TimeoutException("Address check timed out");return left;}
        static string Line(Stream stream,ref int remaining,Stopwatch clock){
            var value=new StringBuilder();int previous=-1;
            while(remaining-->0){int left=Remaining(clock);if(stream.CanTimeout)stream.ReadTimeout=left;int c=stream.ReadByte();if(c<0)throw new EndOfStreamException();if(c==10){if(previous!=13)throw new IOException("Invalid HTTP response");value.Length--;return value.ToString();}if(c!=13&&(c<32||c>126))throw new IOException("Invalid HTTP response");value.Append((char)c);previous=c;}
            throw new IOException("HTTP headers too large");
        }
        internal sealed class HttpStatus {internal int Code;internal string Location;}
        internal static HttpStatus ReadResponse(Stream stream,Stopwatch clock){
            int budget=32768;
            for(int interim=0;interim<4;interim++){
                string status=Line(stream,ref budget,clock);var parts=status.Split(' ');int code;
                if(parts.Length<2||!parts[0].StartsWith("HTTP/1.",StringComparison.Ordinal)||!int.TryParse(parts[1],out code)||code<100||code>599)throw new IOException("Invalid HTTP status");
                string location=null,line;while((line=Line(stream,ref budget,clock)).Length>0)if(line.StartsWith("Location:",StringComparison.OrdinalIgnoreCase))location=line.Substring(9).Trim();
                if(code>=200)return new HttpStatus{Code=code,Location=location};
            }throw new IOException("No final HTTP response");
        }
        internal static string Describe(Uri uri,HttpStatus status,string method){
            int code=status.Code;string prefix="HTTP "+code+(method=="GET"?" (GET вместо HEAD)":"")+": ";
            if(code>=300&&code<400){
                if(code==304)return prefix+"сервер вернул ответ для кэша; откройте страницу в браузере";
                Uri redirect;if(string.IsNullOrWhiteSpace(status.Location)||!Uri.TryCreate(uri,status.Location,out redirect))return prefix+"сервер не сообщил корректный адрес перехода";
                if(redirect.Scheme!="https"||redirect.UserInfo.Length!=0)return prefix+"переход на адрес без HTTPS или с данными входа; переход не выполнен";
                IPAddress literal;if(IPAddress.TryParse(redirect.IdnHost.Trim('[',']'),out literal)&&!IsPublic(literal))return prefix+"переход на внутренний адрес; переход не выполнен";
                bool same=uri.GetLeftPart(UriPartial.Authority).Equals(redirect.GetLeftPart(UriPartial.Authority),StringComparison.OrdinalIgnoreCase);
                return prefix+"переход на "+redirect.AbsoluteUri+(same?"":" (другой домен)")+". Проверьте конечную страницу в браузере";
            }
            if(code==404||code==410)return prefix+"страница не найдена; проверьте путь в адресе";
            if(code==401)return prefix+"сервер требует входа; доступность страницы после входа не проверена";
            if(code==403)return prefix+"доступ к проверке закрыт; возможна защита от автоматических запросов";
            if(code==429)return prefix+"слишком много запросов; повторите проверку позже";
            if(code==405||code==501)return prefix+"сервер не поддерживает этот способ проверки; откройте страницу в браузере";
            if(code>=500)return prefix+"ошибка сервера; повторите позже";
            if(code>=400)return prefix+"сервер отклонил запрос; проверьте ссылку в браузере";
            if(code==204||code==205)return prefix+"сервер ответил без страницы; форма входа не проверена";
            return prefix+"адрес отвечает; заполнение формы ещё не проверено";
        }
        internal static string CheckHttp(Uri uri,Func<string,HttpStatus> request){
            var status=request("HEAD");string method="HEAD";
            if(status.Code==405||status.Code==501){status=request("GET");method="GET";}
            return Describe(uri,status,method);
        }
        static HttpStatus Request(Uri uri,IPAddress[] addresses,string method,Stopwatch clock,CancellationToken cancellation){
            Exception failure=null;
            foreach(var ip in addresses){
                cancellation.ThrowIfCancellationRequested();
                using(var client=new TcpClient(ip.AddressFamily))using(cancellation.Register(client.Close))try{
                    // Use the validated IP; a second DNS lookup could change the destination.
                    if(!client.ConnectAsync(ip,uri.Port).Wait(Remaining(clock),cancellation))throw new TimeoutException("Connection timed out");
                    client.ReceiveTimeout=client.SendTimeout=Remaining(clock);
                    using(var tls=new SslStream(client.GetStream(),false)){
                        if(!tls.AuthenticateAsClientAsync(uri.IdnHost,null,SslProtocols.Tls12,true).Wait(Remaining(clock),cancellation))throw new TimeoutException("TLS timed out");
                        tls.ReadTimeout=tls.WriteTimeout=Remaining(clock);
                        string host=uri.HostNameType==UriHostNameType.IPv6?"["+uri.IdnHost.Trim('[',']')+"]":uri.IdnHost;if(!uri.IsDefaultPort)host+=":"+uri.Port;
                        // Read only bounded headers and close the connection without receiving a page body.
                        string headers=method=="GET"?"Range: bytes=0-0\r\nAccept-Encoding: identity\r\n":"";
                        byte[] request=Encoding.ASCII.GetBytes(method+" "+uri.PathAndQuery+" HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: WinUp address check\r\n"+headers+"Connection: close\r\n\r\n");
                        tls.Write(request,0,request.Length);return ReadResponse(tls,clock);
                    }
                }catch(Exception ex){failure=ex;}
            }if(failure!=null)throw failure;throw new IOException("No connection");
        }
        internal static string Check(string address,CancellationToken cancellation){
            Uri uri;if(!Uri.TryCreate(address,UriKind.Absolute,out uri)||uri.Scheme!="https"||uri.UserInfo.Length!=0||uri.IdnHost.Length>253)return "Нужен HTTPS-адрес без данных входа в ссылке";
            string stage="DNS";
            try{
                cancellation.ThrowIfCancellationRequested();var clock=Stopwatch.StartNew();IPAddress literal;IPAddress[] addresses;
                if(IPAddress.TryParse(uri.IdnHost.Trim('[',']'),out literal))addresses=new[]{literal};
                else{var resolving=Dns.GetHostAddressesAsync(uri.IdnHost);if(!resolving.Wait(Remaining(clock),cancellation))throw new TimeoutException("DNS timed out");addresses=resolving.Result;}
                if(!PublicSet(addresses))return "Внутренний или служебный адрес: проверяется вручную в браузере";
                stage="HTTP";return CheckHttp(uri,method=>Request(uri,addresses,method,clock,cancellation));
            }catch(Exception ex){
                if(cancellation.IsCancellationRequested)return "Проверка отменена";
                Exception reason=ex.GetBaseException();
                if(reason is AuthenticationException)return "Не удалось подтвердить TLS-сертификат сайта; проверьте его в браузере";
                if(reason is TimeoutException)return "Время ожидания истекло; проверьте сеть или повторите позже";
                if(stage=="DNS")return "Не найден адрес сервера; проверьте домен и подключение к сети";
                return "Не удалось получить ответ сайта; проверьте сеть и ссылку в браузере";
            }
        }
    }
}
