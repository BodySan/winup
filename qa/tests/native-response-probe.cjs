const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=process.argv[2];
if(!root)throw Error('Pass the isolated native encoding probe folder');
function decode(buf){let i=0;function one(){const first=buf[i++],major=first>>5;let n=first&31;if(n===24)n=buf[i++];else if(n===25){n=buf.readUInt16BE(i);i+=2;}else if(n===26){n=buf.readUInt32BE(i);i+=4;}if(major===0)return n;if(major===1)return -1-n;if(major===2||major===3){const value=buf.subarray(i,i+n);i+=n;return major===2?value:value.toString();}if(major===4)return Array.from({length:n},one);if(major===5){const value={};for(let j=0;j<n;j++)value[one()]=one();return value;}if(major===7&&n===20)return false;if(major===7&&n===21)return true;throw Error('Unsupported CBOR');}const value=one();if(i!==buf.length)throw Error('Trailing response bytes');return value;}
const expected=JSON.parse(fs.readFileSync(path.join(root,'encoding-public.json'),'utf8'));
const create=decode(fs.readFileSync(path.join(root,'encoded-create.cbor'))),get=decode(fs.readFileSync(path.join(root,'encoded-get.cbor')));
if(process.argv.includes('--inspect'))console.log(JSON.stringify({keys:Object.keys(get),userHandle:get[4]?.id?.toString('base64url'),numberOfCredentials:get[5],userSelected:get[6]}));
function check(name,ok){if(!ok)throw Error(name);console.log('PASS '+name);}
const bytes=value=>Buffer.from(value,'base64url');
check('Windows registration response has CTAP format and empty attestation statement',create[1]==='none'&&create[3]&&Object.keys(create[3]).length===0);
check('Windows registration preserves authenticator data and credential ID',create[2].equals(bytes(expected.createAuth))&&create[2].subarray(55,87).equals(bytes(expected.id)));
check('Windows assertion preserves credential and authenticator data',get[1].id.equals(bytes(expected.id))&&get[1].type==='public-key'&&get[2].equals(bytes(expected.getAuth)));
check('Windows assertion carries the selected user',get[4].id.equals(bytes(expected.userId))&&(get[5]===undefined||get[5]===1)&&get[6]===true);
check('Windows assertion signature verifies independently',crypto.verify('sha256',Buffer.concat([get[2],bytes(expected.hash)]),crypto.createPublicKey({key:bytes(expected.publicKey),type:'spki',format:'der'}),get[3]));
