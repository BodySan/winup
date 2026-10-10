// Windows COM ABI and platform signature verification adapted from KeePassPasskey
// (Uwe Koegel, GPL-3.0-or-later), commit 08a3e0b13b81ee55929c4e9e0895e7197118b3b6.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using WinUp.SystemPasskeyNative;
#if PASSKEY_PROVIDER
using Engine=WinUp.ProviderPublicData;
#else
using Engine=WinUp.PasskeyEngine.Keys;
#endif

namespace WinUp {
    [ComVisible(true),Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IWinUpPluginAuthenticator {
        [PreserveSig]int MakeCredential(IntPtr request,IntPtr response);
        [PreserveSig]int GetAssertion(IntPtr request,IntPtr response);
        [PreserveSig]int CancelOperation(IntPtr request);
        [PreserveSig]int GetLockStatus(IntPtr status);
    }
    [ComVisible(true),Guid("00000001-0000-0000-C000-000000000046"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IWinUpClassFactory {
        [PreserveSig]int CreateInstance(IntPtr outer,ref Guid iid,out IntPtr result);
        [PreserveSig]int LockServer(bool value);
    }
    [ComVisible(true),ClassInterface(ClassInterfaceType.None)]
    public sealed class WinUpPasskeyFactory:IWinUpClassFactory {
        public int CreateInstance(IntPtr outer,ref Guid iid,out IntPtr result){SystemPasskeyProvider.Touch();result=IntPtr.Zero;if(outer!=IntPtr.Zero)return unchecked((int)0x80040110);if(iid!=ComIids.IID_IUnknown&&iid!=ComIids.IID_IPluginAuthenticator)return unchecked((int)0x80004002);result=Marshal.GetComInterfaceForObject(new WinUpPluginAuthenticator(),typeof(IWinUpPluginAuthenticator));return 0;}
        public int LockServer(bool value){return 0;}
    }
    [ComVisible(true),ClassInterface(ClassInterfaceType.None)]
    public sealed unsafe class WinUpPluginAuthenticator:IWinUpPluginAuthenticator {
        const int Cancelled=unchecked((int)0x80090036),BadSignature=unchecked((int)0x80090006);
        static readonly object sync=new object();static readonly Dictionary<Guid,byte[]> running=new Dictionary<Guid,byte[]>();
        internal static byte[] Bytes(byte* pointer,uint count,int maximum){if(count>maximum||pointer==null&&count!=0)throw new IOException("Invalid platform request");var bytes=new byte[count];if(count>0)Marshal.Copy((IntPtr)pointer,bytes,0,(int)count);return bytes;}
        static byte[] SigningKey(bool verification){Guid clsid=SystemPasskeyProvider.Clsid;uint count=0;byte* pointer=null;int hr=verification?WebAuthnPluginApi.WebAuthNPluginGetUserVerificationPublicKey(ref clsid,&count,&pointer):WebAuthnPluginApi.WebAuthNPluginGetOperationSigningPublicKey(ref clsid,&count,&pointer);if(hr<0||pointer==null)throw new IOException("Windows signing key unavailable");try{return Bytes(pointer,count,65536);}finally{WebAuthnPluginApi.WebAuthNPluginFreePublicKeyResponse(pointer);}}
        internal static bool VerifySignature(byte[] data,byte[] blob,byte[] signature){using(var sha=SHA256.Create()){var hash=sha.ComputeHash(data);using(var key=CngKey.Import(blob,CngKeyBlobFormat.GenericPublicBlob)){if(blob.Length>=4&&BitConverter.ToUInt32(blob,0)==0x31415352){using(var rsa=new RSACng(key))return rsa.VerifyHash(hash,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pss)||rsa.VerifyHash(hash,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);}using(var ec=new ECDsaCng(key))return ec.VerifyHash(hash,signature);}}}
        internal static string Utf8(byte* pointer,uint count){return Encoding.UTF8.GetString(Bytes(pointer,count,4096));}
        static string Text(char* pointer){if(pointer==null)return "";string text=new string(pointer);if(text.Length>4096)throw new IOException("Platform text too long");return text;}
        static string[] CredentialIds(WebAuthnCredentialList list){if(list.cCredentials>1024)throw new IOException("Too many credentials");var result=new List<string>();for(uint i=0;i<list.cCredentials;i++){var item=list.ppCredentials[i];if(item!=null&&Text(item->pwszCredentialType)=="public-key")result.Add(PasskeyPolicy.Encode(Bytes(item->pbId,item->cbId,1024)));}return result.ToArray();}
        static bool IsCancelled(Guid id){lock(sync)return !running.ContainsKey(id);}
        internal static int EncodeRegistration(byte[] auth,byte[] credential,out uint length,out IntPtr result){
            uint count=0;byte* encoded=null;int hr;
            fixed(byte* authP=auth)fixed(char* format="none"){
                var value=new WebAuthnCredentialAttestation{dwVersion=WebAuthnConstants.AttestationCurrentVersion,pwszFormatType=format,cbAuthenticatorData=(uint)auth.Length,pbAuthenticatorData=authP};
                hr=WebAuthnPluginApi.WebAuthNEncodeMakeCredentialResponse(&value,&count,&encoded);
            }length=count;result=(IntPtr)encoded;return hr;
        }
        internal static int EncodeAssertion(byte[] auth,byte[] credential,byte[] signature,byte[] userId,out uint length,out IntPtr result){
            uint count=0;byte* encoded=null;int hr;
            fixed(byte* authP=auth)fixed(byte* sigP=signature)fixed(byte* credentialP=credential)fixed(byte* userP=userId)fixed(char* type="public-key")fixed(char* name=""){
                var user=new WebAuthnUserEntityInformation{dwVersion=1,cbId=(uint)userId.Length,pbId=userP,pwszName=name,pwszDisplayName=name};
                var value=new WebAuthnCtapCborGetAssertionResponse{WebAuthNAssertion=new WebAuthnAssertion{dwVersion=WebAuthnConstants.AssertionCurrentVersion,cbAuthenticatorData=(uint)auth.Length,pbAuthenticatorData=authP,cbSignature=(uint)signature.Length,pbSignature=sigP,cbUserId=(uint)userId.Length,pbUserId=userP,Credential=new WebAuthnCredential{dwVersion=1,cbId=(uint)credential.Length,pbId=credentialP,pwszCredentialType=type}},pUserInformation=&user,dwNumberOfCredentials=1,lUserSelected=1};
                hr=WebAuthnPluginApi.WebAuthNEncodeGetAssertionResponse(&value,&count,&encoded);
            }length=count;result=(IntPtr)encoded;return hr;
        }
        int Operate(bool create,IntPtr requestRaw,IntPtr responseRaw){
            SystemPasskeyProvider.BeginOperation();
            if(requestRaw==IntPtr.Zero||responseRaw==IntPtr.Zero){SystemPasskeyProvider.EndOperation();return unchecked((int)0x80070057);}var request=(WebAuthnPluginOperationRequest*)requestRaw;var response=(WebAuthnPluginOperationResponse*)responseRaw;*response=new WebAuthnPluginOperationResponse();Guid id=request->transactionId;byte[] encoded=null;
            try{if(request->requestType!=WebAuthnPluginRequestType.Ctap2Cbor)return unchecked((int)0x80070057);encoded=Bytes(request->pbEncodedRequest,request->cbEncodedRequest,65536);if(!VerifySignature(encoded,SigningKey(false),Bytes(request->pbRequestSignature,request->cbRequestSignature,8192)))return BadSignature;
                lock(sync){if(running.ContainsKey(id))return unchecked((int)0x800700AA);running.Add(id,encoded);}
                var message=new Dictionary<string,object>{{"action","system_passkey"},{"create",create},{"transaction",id.ToString("D")}};
                if(create){WebAuthnCtapCborMakeCredentialRequest* decoded=null;int hr=WebAuthnPluginApi.WebAuthNDecodeMakeCredentialRequest(request->cbEncodedRequest,request->pbEncodedRequest,&decoded);if(hr<0)return hr;try{if(decoded==null||decoded->pUserInformation==null||decoded->pRpInformation==null||decoded->cbClientDataHash!=32)return unchecked((int)0x80070057);message["rp"]=Utf8(decoded->pbRpId,decoded->cbRpId);message["rpName"]=Text(decoded->pRpInformation->pwszName);message["user"]=Text(decoded->pUserInformation->pwszName);message["userDisplay"]=Text(decoded->pUserInformation->pwszDisplayName);message["userId"]=PasskeyPolicy.Encode(Bytes(decoded->pUserInformation->pbId,decoded->pUserInformation->cbId,64));message["hash"]=PasskeyPolicy.Encode(Bytes(decoded->pbClientDataHash,32,32));message["ids"]=CredentialIds(decoded->CredentialList);if(decoded->WebAuthNCredentialParameters.cCredentialParameters>128)return unchecked((int)0x80070057);var algorithms=new List<int>();for(uint i=0;i<decoded->WebAuthNCredentialParameters.cCredentialParameters;i++)algorithms.Add(decoded->WebAuthNCredentialParameters.pCredentialParameters[i].lAlg);message["algorithms"]=algorithms.ToArray();}finally{if(decoded!=null)WebAuthnPluginApi.WebAuthNFreeDecodedMakeCredentialRequest(decoded);}}
                else{WebAuthnCtapCborGetAssertionRequest* decoded=null;int hr=WebAuthnPluginApi.WebAuthNDecodeGetAssertionRequest(request->cbEncodedRequest,request->pbEncodedRequest,&decoded);if(hr<0)return hr;try{if(decoded==null||decoded->cbClientDataHash!=32)return unchecked((int)0x80070057);message["rp"]=Utf8(decoded->pbRpId,decoded->cbRpId);message["hash"]=PasskeyPolicy.Encode(Bytes(decoded->pbClientDataHash,32,32));message["ids"]=CredentialIds(decoded->CredentialList);}finally{if(decoded!=null)WebAuthnPluginApi.WebAuthNFreeDecodedGetAssertionRequest(decoded);}}
                if(IsCancelled(id))return Cancelled;var reply=SystemPasskeyProvider.Call(message);if(IsCancelled(id))return Cancelled;if(!reply.ContainsKey("ok")||!(bool)reply["ok"])return Cancelled;
                byte[] auth=Decode((string)reply["auth"],4096),credential=Decode((string)reply["id"],1024);uint length=0;byte* result=null;int encodeHr;
                IntPtr encodedResult;
                if(create)encodeHr=EncodeRegistration(auth,credential,out length,out encodedResult);
                else{byte[] signature=Decode((string)reply["signature"],4096),userId=Decode((string)reply["userId"],64);encodeHr=EncodeAssertion(auth,credential,signature,userId,out length,out encodedResult);}
                result=(byte*)encodedResult;
                if(encodeHr<0)return encodeHr;response->cbEncodedResponse=length;response->pbEncodedResponse=result;return 0;
            }catch(Exception ex){return Marshal.GetHRForException(ex);}finally{lock(sync)running.Remove(id);if(encoded!=null)Array.Clear(encoded,0,encoded.Length);SystemPasskeyProvider.EndOperation();}
        }
        public int MakeCredential(IntPtr request,IntPtr response){return Operate(true,request,response);}
        internal static byte[] Decode(string value,int maximum){var bytes=PasskeyPolicy.Decode(value,0,maximum);if(bytes.Length>maximum)throw new IOException("Platform response too large");return bytes;}
        public int GetAssertion(IntPtr request,IntPtr response){return Operate(false,request,response);}
        public int CancelOperation(IntPtr requestRaw){if(requestRaw==IntPtr.Zero)return unchecked((int)0x80070057);try{var request=(WebAuthnPluginCancelOperationRequest*)requestRaw;byte[] encoded;lock(sync){if(!running.TryGetValue(request->transactionId,out encoded))return 0;encoded=(byte[])encoded.Clone();}try{if(!VerifySignature(encoded,SigningKey(false),Bytes(request->pbRequestSignature,request->cbRequestSignature,8192)))return BadSignature;lock(sync)running.Remove(request->transactionId);SystemPasskeyProvider.Call(new Dictionary<string,object>{{"action","system_cancel"},{"transaction",request->transactionId.ToString("D")}});return 0;}finally{Array.Clear(encoded,0,encoded.Length);}}catch(Exception ex){return Marshal.GetHRForException(ex);}}
        public int GetLockStatus(IntPtr status){SystemPasskeyProvider.Touch();if(status==IntPtr.Zero)return unchecked((int)0x80070057);bool ready=false;try{var result=SystemPasskeyProvider.Call(new Dictionary<string,object>{{"action","system_status"}});ready=result.ContainsKey("ready")&&(bool)result["ready"];}catch{}Marshal.WriteInt32(status,ready?1:0);return 0;}
    }
    internal static unsafe class SystemPasskeyProvider {
        internal static Guid Clsid=new Guid("3bed5836-6fa2-4af8-b271-53c727e5adb8");
        static long lastUsed=DateTime.UtcNow.Ticks;static int operations;
        internal static void Touch(){Interlocked.Exchange(ref lastUsed,DateTime.UtcNow.Ticks);}
        internal static void BeginOperation(){Interlocked.Increment(ref operations);Touch();}
        internal static void EndOperation(){Interlocked.Decrement(ref operations);Touch();}
        internal static int Remove(){return WebAuthnPluginApi.WebAuthNPluginRemoveAuthenticator(ref Clsid);}
        [DllImport("ole32.dll")]static extern int CoRegisterClassObject(ref Guid clsid,IntPtr factory,uint context,uint flags,out uint cookie);
        [DllImport("ole32.dll")]static extern int CoRevokeClassObject(uint cookie);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFullName(IntPtr process,ref int count,StringBuilder name);
#if !PASSKEY_PROVIDER
        internal static bool IsClient(int pid){try{if(!SystemPasskeySetup.IsProviderFile(Proc.ImagePath(pid)))return false;using(var process=System.Diagnostics.Process.GetProcessById(pid)){int count=0;GetPackageFullName(process.Handle,ref count,null);if(count<1||count>1000)return false;var name=new StringBuilder(count);return GetPackageFullName(process.Handle,ref count,name)==0&&name.ToString().StartsWith("WinUp.Passkeys_",StringComparison.Ordinal)&&name.ToString().EndsWith("__vgx8a7xnkd0yg",StringComparison.Ordinal);}}catch{return false;}}
#endif
        internal static Dictionary<string,object> Call(Dictionary<string,object> request){using(var pipe=new NamedPipeClientStream(".",BrowserPipe.Name,PipeDirection.InOut,PipeOptions.Asynchronous)){pipe.Connect(3000);if(!Proc.SameFile(Proc.ImagePath(Proc.ServerPid(pipe)),Path.Combine(Paths.Root,"WinUp.exe")))throw new IOException("WinUp server is not trusted");var js=new JavaScriptSerializer{MaxJsonLength=256*1024};byte[] bytes=Encoding.UTF8.GetBytes(js.Serialize(request)+"\n");try{pipe.Write(bytes,0,bytes.Length);pipe.Flush();}finally{Array.Clear(bytes,0,bytes.Length);}using(var data=new MemoryStream()){var buffer=new byte[4096];var clock=System.Diagnostics.Stopwatch.StartNew();int timeout=(string)request["action"]=="system_status"?5000:180000;try{while(data.Length<256*1024){var pending=pipe.BeginRead(buffer,0,Math.Min(buffer.Length,256*1024-(int)data.Length),null,null);using(var done=pending.AsyncWaitHandle){int remaining=timeout-(int)clock.ElapsedMilliseconds;if(remaining<1||!done.WaitOne(remaining))throw new IOException("WinUp response timed out");int count=pipe.EndRead(pending);if(count==0)throw new IOException("WinUp did not answer");int end=Array.IndexOf(buffer,(byte)'\n',0,count);data.Write(buffer,0,end<0?count:end);if(end>=0)return js.Deserialize<Dictionary<string,object>>(new UTF8Encoding(false,true).GetString(data.GetBuffer(),0,(int)data.Length));}}throw new IOException("WinUp response too large");}finally{Array.Clear(buffer,0,buffer.Length);Array.Clear(data.GetBuffer(),0,(int)data.Length);}}}}
        internal static int Register(){Guid id=Clsid;byte[] info=Engine.SystemAuthenticatorInfo();fixed(byte* data=info)fixed(char* name="WinUp")fixed(char* rp="winup.local"){var options=new WebAuthnPluginAddAuthenticatorOptions{pwszAuthenticatorName=name,rclsid=&id,pwszPluginRpId=rp,cbAuthenticatorInfo=(uint)info.Length,pbAuthenticatorInfo=data};WebAuthnPluginAddAuthenticatorResponse* response=null;int hr=WebAuthnPluginApi.WebAuthNPluginAddAuthenticator(&options,&response);if(response!=null)WebAuthnPluginApi.WebAuthNPluginFreeAddAuthenticatorResponse(response);return hr;}}
        internal static void Run(){Application.EnableVisualStyles();var factory=new WinUpPasskeyFactory();IntPtr pointer=Marshal.GetComInterfaceForObject(factory,typeof(IWinUpClassFactory));uint cookie;int hr=CoRegisterClassObject(ref Clsid,pointer,4,1,out cookie);Marshal.Release(pointer);if(hr<0)Marshal.ThrowExceptionForHR(hr);using(var timer=new System.Windows.Forms.Timer{Interval=30000}){timer.Tick+=(s,e)=>{if(Interlocked.CompareExchange(ref operations,0,0)==0&&DateTime.UtcNow.Ticks-Interlocked.Read(ref lastUsed)>TimeSpan.FromMinutes(10).Ticks)Application.ExitThread();};timer.Start();try{Application.Run();}finally{CoRevokeClassObject(cookie);GC.KeepAlive(factory);}}}
    }
}
