// WinUp adapter around GPL-3.0-or-later KeePassPasskey cryptographic helpers.
using System;
using KeePassPasskey.Passkey;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Passkey;
using PeterO.Cbor;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace WinUp.PasskeyEngine {
    public static class Keys {
        // One RFC 4122 model identifier for WinUp's software authenticator.
        // It identifies this implementation, never a user, device or credential.
        // Do not borrow an upstream or platform provider's identity. Existing
        // credentials keep their original registration data; assertions have
        // no AAGUID and their backup flags are read from the saved entry.
        static readonly byte[] ModelAaguid = {
            0xd4,0x9d,0xfb,0x48,0x1e,0xc0,0x40,0xa6,
            0xac,0xe0,0xb4,0x72,0x03,0xe4,0x34,0xe1
        };
        public static void Generate(int algorithm, out string pem, out byte[] cose, out byte[] spki) {
            var alg=(PasskeyAlgorithm)algorithm;
            var pair=PasskeyKeyHelper.GenerateKeyPair(alg);
            pem=pair.privateKeyPem; cose=PasskeyKeyHelper.BuildCoseKey(alg,pair.pub);
            Org.BouncyCastle.Crypto.AsymmetricKeyParameter key;
            if(alg==PasskeyAlgorithm.ES256) {
                var c=NistNamedCurves.GetByName("P-256");
                var domain=new ECNamedDomainParameters(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.2.840.10045.3.1.7"),c);
                byte[] q=new byte[65]; q[0]=4; Array.Copy(pair.pub.X,0,q,1,32); Array.Copy(pair.pub.Y,0,q,33,32);
                key=new ECPublicKeyParameters(c.Curve.DecodePoint(q),domain);
            } else if(alg==PasskeyAlgorithm.EdDSA) key=new Ed25519PublicKeyParameters(pair.pub.EdPublicKey,0);
            else key=new RsaKeyParameters(false,new Org.BouncyCastle.Math.BigInteger(1,pair.pub.N),new Org.BouncyCastle.Math.BigInteger(1,pair.pub.E));
            spki=SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetEncoded();
        }
        public static byte[] RegisterData(string rp, byte[] id, byte[] cose) {
            return AuthenticatorData.BuildForRegistration(rp,ModelAaguid,id,cose,true,false);
        }
        public static byte[] AssertionData(string rp, bool eligible, bool backedUp) { return AuthenticatorData.BuildForAuthentication(rp,0,eligible,eligible && backedUp); }
        public static byte[] Attestation(byte[] auth) {
            var obj=CBORObject.NewMap().Add("fmt","none").Add("attStmt",CBORObject.NewMap()).Add("authData",auth);
            return obj.EncodeToBytes(new CBOREncodeOptions("ctap2canonical=true"));
        }
        public static byte[] Sign(string pem, byte[] data) { return PasskeyKeyHelper.Sign(pem,data); }
    }
}
