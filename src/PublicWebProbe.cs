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
        static int Remaining(Stopwatch clock){int left=7000-(int)clock.ElapsedMilliseconds;if(left<=0)throw new IOException("Address check timed out");return left;}
        static string Line(Stream stream,ref int remaining,Stopwatch clock){
            var value=new StringBuilder();int previous=-1;
            while(remaining-->0){int left=Remaining(clock);if(stream.CanTimeout)stream.ReadTimeout=left;int c=stream.ReadByte();if(c<0)throw new EndOfStreamException();if(c==10){if(previous!=13)throw new IOException("Invalid HTTP response");value.Length--;return value.ToString();}if(c!=13&&(c<32||c>126))throw new IOException("Invalid HTTP response");value.Append((char)c);previous=c;}
            throw new IOException("HTTP headers too large");
        }
        internal static string Check(string address,CancellationToken cancellation){
            Uri uri;
            if(!Uri.TryCreate(address,UriKind.Absolute,out uri)||uri.Scheme!="https"||uri.UserInfo.Length!=0||uri.IdnHost.Length>253)
                return "Для сетевой проверки нужен HTTPS-адрес сайта без данных входа в ссылке";
            try{
                cancellation.ThrowIfCancellationRequested();var clock=Stopwatch.StartNew();IPAddress literal;IPAddress[] addresses;
                if(IPAddress.TryParse(uri.IdnHost.Trim('[',']'),out literal))addresses=new[]{literal};
                else{var resolving=Dns.GetHostAddressesAsync(uri.IdnHost);if(!resolving.Wait(Remaining(clock),cancellation))throw new IOException("DNS timed out");addresses=resolving.Result;}
                if(!PublicSet(addresses))return "Локальный, внутренний или служебный адрес: проверьте его вручную в браузере";
                Exception failure=null;
                foreach(var ip in addresses){
                    cancellation.ThrowIfCancellationRequested();
                    using(var client=new TcpClient(ip.AddressFamily))using(cancellation.Register(client.Close))try{
                        // Connect to the validated IP itself: DNS must not be
                        // repeated by an HTTP library after the policy check.
                        if(!client.ConnectAsync(ip,uri.Port).Wait(Remaining(clock),cancellation))throw new IOException("Connection timed out");
                        client.ReceiveTimeout=client.SendTimeout=Remaining(clock);
                        using(var tls=new SslStream(client.GetStream(),false)){
                            if(!tls.AuthenticateAsClientAsync(uri.IdnHost,null,SslProtocols.Tls12,true).Wait(Remaining(clock),cancellation))throw new IOException("TLS timed out");
                            tls.ReadTimeout=tls.WriteTimeout=Remaining(clock);
                            string host=uri.HostNameType==UriHostNameType.IPv6?"["+uri.IdnHost.Trim('[',']')+"]":uri.IdnHost;
                            if(!uri.IsDefaultPort)host+=":"+uri.Port;
                            byte[] request=Encoding.ASCII.GetBytes("HEAD "+uri.PathAndQuery+" HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: WinUp address check\r\nConnection: close\r\n\r\n");
                            tls.Write(request,0,request.Length);int budget=32768;string status=Line(tls,ref budget,clock);var parts=status.Split(' ');int code;
                            if(parts.Length<2||!parts[0].StartsWith("HTTP/1.",StringComparison.Ordinal)||!int.TryParse(parts[1],out code)||code<100||code>599)throw new IOException("Invalid HTTP status");
                            string location=null,line;while((line=Line(tls,ref budget,clock)).Length>0)if(line.StartsWith("Location:",StringComparison.OrdinalIgnoreCase))location=line.Substring(9).Trim();
                            if(code>=300&&code<400)return "HTTP "+code+": переход на "+(location??"другую страницу")+" — проверьте в браузере";
                            if(code==405||code==501)return "HTTP "+code+": сайт не поддерживает проверку HEAD; откройте ссылку в браузере";
                            if(code==401||code==403||code==429)return "HTTP "+code+": сайт ограничил проверку; адрес может работать в браузере";
                            return "HTTP "+code+(code>=400?": возможная ошибка адреса":": адрес отвечает; форму входа проверьте в браузере");
                        }
                    }catch(Exception ex){failure=ex;}
                }
                if(failure!=null)throw failure;return "Не удалось подключиться";
            }catch(Exception){return cancellation.IsCancellationRequested?"Проверка отменена":"Не удалось проверить адрес напрямую: проверьте сеть и ссылку в браузере";}
        }
    }
}
