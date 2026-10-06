// Independent relying-party verifier, loopback only, synthetic accounts.
const http=require('http'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const keys=new Map(),challenge=Buffer.from(Array.from({length:32},(_,i)=>i+1));
const output=process.argv[2];
const page=`<!doctype html><meta charset="utf-8"><title>WinUp synthetic passkeys</title>
<button id="create">Create</button><button id="get">Get</button><button id="bad">Wrong RP</button><pre id="result"></pre>
<input autocomplete="one-time-code" id="otp" name="otp"><script>
const challenge=Uint8Array.from({length:32},(_,i)=>i+1);
async function run(create){try{
const options=create ? {challenge,rp:{id:'localhost',name:'Synthetic RP'},user:{id:new Uint8Array([1,2,3,4]),name:'sandbox-user',displayName:'Sandbox user'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none'} : {challenge,rpId:'localhost',userVerification:'required'};
const credential=await navigator.credentials[create?'create':'get']({publicKey:options});
const proof=credential.toJSON(); const response=await fetch('/verify',{method:'POST',body:JSON.stringify({create,proof})});
document.querySelector('#result').textContent=await response.text();
}catch(e){document.querySelector('#result').textContent=e.name+':'+e.message;}}
document.querySelector('#create').onclick=()=>run(true); document.querySelector('#get').onclick=()=>run(false);
document.querySelector('#bad').onclick=async()=>{try{await navigator.credentials.create({publicKey:{challenge,rp:{id:'example.com',name:'Wrong RP'},user:{id:new Uint8Array([1]),name:'sandbox-user',displayName:'Sandbox'},pubKeyCredParams:[{type:'public-key',alg:-7}]}});document.querySelector('#result').textContent='UNEXPECTED_SUCCESS'}catch(e){document.querySelector('#result').textContent=e.name}};
</script>`;
function decode(buf){let i=0;function one(){const first=buf[i++],major=first>>5;let n=first&31;if(n===24)n=buf[i++];else if(n===25){n=buf.readUInt16BE(i);i+=2;}else if(n===26){n=buf.readUInt32BE(i);i+=4;}if(major===0)return n;if(major===1)return -1-n;if(major===2||major===3){const b=buf.subarray(i,i+n);i+=n;return major===2?b:b.toString();}if(major===4)return Array.from({length:n},one);if(major===5){const o={};for(let j=0;j<n;j++)o[one()]=one();return o;}throw Error('unsupported CBOR');}return one();}
function verify(create,proof){
 const r=proof.response,client=Buffer.from(r.clientDataJSON,'base64url'),data=JSON.parse(client);
 if(data.origin!=='http://localhost:9265'||data.type!==(create?'webauthn.create':'webauthn.get')||data.challenge!==challenge.toString('base64url')||data.crossOrigin!==false)throw Error('client data mismatch');
 const auth=Buffer.from(r.authenticatorData,'base64url');
 if(!auth.subarray(0,32).equals(crypto.createHash('sha256').update('localhost').digest())||(auth[32]&5)!==5)throw Error('RP hash or user verification mismatch');
 if(create){
  const att=decode(Buffer.from(r.attestationObject,'base64url')); if(att.fmt!=='none'||!att.authData.equals(auth))throw Error('attestation mismatch');
  const length=auth.readUInt16BE(53),id=auth.subarray(55,55+length); if(id.toString('base64url')!==proof.id)throw Error('credential ID mismatch');
  const cose=decode(auth.subarray(55+length)),spki=Buffer.from(r.publicKey,'base64url');
  const publicKey=crypto.createPublicKey({key:spki,type:'spki',format:'der'}),jwk=publicKey.export({format:'jwk'});
  if(cose[3]!==-7||cose[-2].toString('base64url')!==jwk.x||cose[-3].toString('base64url')!==jwk.y)throw Error('COSE and SPKI disagree');
  keys.set(proof.id,publicKey);
 }else{
  const key=keys.get(proof.id);if(!key)throw Error('unknown credential');
  if(!crypto.verify('sha256',Buffer.concat([auth,crypto.createHash('sha256').update(client).digest()]),key,Buffer.from(r.signature,'base64url')))throw Error('invalid signature');
  if(r.userHandle!=='AQIDBA')throw Error('wrong account');
 }
 return create?'PASS registration verified':'PASS signature verified';
}
http.createServer((req,res)=>{if(req.method==='GET'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(page);return;}let body='';req.on('data',b=>{body+=b;if(body.length>65536)req.destroy();});req.on('end',()=>{try{const {create,proof}=JSON.parse(body);const result=verify(create,proof);if(output)fs.appendFileSync(path.join(output,'browser-proof.txt'),result+'\n');res.end(result);}catch(e){res.statusCode=400;res.end('FAIL '+e.message);}});}).listen(9265,'127.0.0.1');
