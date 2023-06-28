using System;
using System.Net;
using System.Collections.Generic;
using NebulaNetworkAutomation;

namespace NebulaNetworkAutomation
{
    public class CNebulaCert
    {
        const string c_NebulaCertID = "NEBULA CERTIFICATE";
        const string c_NebulaCAKeyID = "NEBULA ED25519 PRIVATE KEY";
        const string c_NebulaKeyID = "NEBULA X25519 PRIVATE KEY";

        RawNebulaCertificate? m_cert = null;
        byte[]? m_private_key = null;
        //-----------------------------------------------------------------------
        CNebulaCert(RawNebulaCertificate inCert, byte[] inKey)
        {
            m_cert = inCert;
            m_private_key = inKey;
        }
        //-----------------------------------------------------------------------
        static public CNebulaCert? MakeCA(in string inName, in DateTime StartDate, in TimeSpan ValidityPeriod)
        {
            var gen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
            gen.Init(new Org.BouncyCastle.Crypto.Parameters.Ed25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
            var pair = gen.GenerateKeyPair();

            var privateKey = (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters)pair.Private;
            var publicKey = (Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)pair.Public;


            byte[] prv_key = privateKey.GetEncoded();
            byte[] pub_key = publicKey.GetEncoded();

            RawNebulaCertificate raw_cert = new RawNebulaCertificate();
            raw_cert.Details = new RawNebulaCertificateDetails();
            raw_cert.Details.Name = inName;

            raw_cert.Details.NotBefore =
                //(long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
                (long)StartDate.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            raw_cert.Details.NotAfter =
                //(long)DateTime.UtcNow.AddYears(1).Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
                (long)StartDate.Add(ValidityPeriod).Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

            raw_cert.Details.PublicKey = Google.Protobuf.ByteString.CopyFrom(pub_key);
            raw_cert.Details.IsCA = true;
            raw_cert.Details.Curve = Curve._25519;


            raw_cert.Signature = GetPBSig(raw_cert.Details, privateKey);
            if ((raw_cert.Signature == null) || (raw_cert.Signature.Length == 0))
                return null;

            return new CNebulaCert(raw_cert, prv_key);
        }
        //-----------------------------------------------------------------------
        static public CNebulaCert? MakeSignedCert(in CNebulaCert inCA, in string inName, in IPAddress inIP, in int inCidr, in DateTime StartDate, in TimeSpan ValidityPeriod)
        {
            if (inCA == null)
                return null;
            if (!inCA.IsValidCA())
                return null;

            var gen = new Org.BouncyCastle.Crypto.Generators.X25519KeyPairGenerator();
            gen.Init(new Org.BouncyCastle.Crypto.Parameters.X25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
            var pair = gen.GenerateKeyPair();

            var privateKey = (Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters)pair.Private;
            var publicKey = (Org.BouncyCastle.Crypto.Parameters.X25519PublicKeyParameters)pair.Public;

            byte[] prv_key = privateKey.GetEncoded();
            byte[] pub_key = publicKey.GetEncoded();

            DateTime? caStartDate = inCA.GetStartDate();
            if (caStartDate == null)
                return null;
            DateTime? caEndDate = inCA.GetEndDate();
            if (caEndDate == null)
                return null;

            DateTime accStartDate;
            DateTime accEndDate;
            if (StartDate < caStartDate)
            {
                accStartDate = caStartDate.Value;
                accEndDate = accStartDate + ValidityPeriod.Subtract(caStartDate.Value - StartDate);
            }
            else
            {
                accStartDate = StartDate;
                accEndDate = StartDate + ValidityPeriod;
            }
            if (accEndDate > caEndDate)
                accEndDate = caEndDate.Value;


            RawNebulaCertificate raw_cert = new RawNebulaCertificate();
            raw_cert.Details = new RawNebulaCertificateDetails();

            raw_cert.Details.Name = inName;
            raw_cert.Details.Ips.Add((uint)IPNetwork.ToBigInteger(inIP));
            raw_cert.Details.Ips.Add((uint)IPNetwork.ToBigInteger(
                IPNetwork.ToNetmask((byte)inCidr, System.Net.Sockets.AddressFamily.InterNetwork)));

            raw_cert.Details.NotBefore =
                //(long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
                (long)accStartDate.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            raw_cert.Details.NotAfter =
                //(long)inCA.GetEndDate().Subtract(TimeSpan.FromSeconds(1)).Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
                (long)accEndDate.Subtract(TimeSpan.FromSeconds(1)).Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

            raw_cert.Details.PublicKey = Google.Protobuf.ByteString.CopyFrom(pub_key);
            raw_cert.Details.IsCA = false;
            raw_cert.Details.Issuer = Google.Protobuf.ByteString.CopyFrom(inCA.GetSHA256());
            raw_cert.Details.Curve = Curve._25519;


            raw_cert.Signature = GetPBSig(raw_cert.Details, new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(inCA.m_private_key));
            if ((raw_cert.Signature == null) || (raw_cert.Signature.Length == 0))
                return null;

            return new CNebulaCert(raw_cert, prv_key);
        }
        //-----------------------------------------------------------------------
        static public CNebulaCert? MakeFromPEM(in string inCert, in string? inPrivateKey = null)
        {
            CPEM? p = CPEM.FromString(inCert, c_NebulaCertID);
            if (p == null)
                return null;
            try
            {
                RawNebulaCertificate rawCert = RawNebulaCertificate.Parser.ParseFrom(p.Bytes);
                if (rawCert == null)
                    return null;

                byte[]? nebulaKey = null;

                if (rawCert.Details.IsCA)
                {
                    if (inPrivateKey != null)
                    {
                        nebulaKey = CPEM.FromString(inPrivateKey, c_NebulaCAKeyID)?.Bytes;
                        if (nebulaKey == null)
                            return null;


                        int keySizePrv = Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters.KeySize;
                        int keySizePub = Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters.KeySize;

                        if (nebulaKey.Length != (keySizePrv + keySizePub))
                            return null;

                        nebulaKey = nebulaKey.AsSpan(0, keySizePrv).ToArray();
                    }
                }
                else
                {
                    if (inPrivateKey != null)
                    {
                        nebulaKey = CPEM.FromString(inPrivateKey, c_NebulaKeyID)?.Bytes;
                        if (nebulaKey == null)
                            return null;

                        if (nebulaKey.Length != Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters.KeySize)
                            return null;
                    }
                }
                if (nebulaKey == null)
                    return null;

                return new CNebulaCert(rawCert, nebulaKey);
            }
            catch
            {
                return null;
            }
        }
        //-----------------------------------------------------------------------
        public string? GetCertPEM()
        {
            if (m_cert == null)
                return null;
            byte[] o = new byte[m_cert.CalculateSize()];
            m_cert.WriteTo(new Google.Protobuf.CodedOutputStream(o));
            return CPEM.FromBytes(o, c_NebulaCertID)?.PEM;
        }
        //-----------------------------------------------------------------------
        public string? GetPrivateKeyPem()
        {
            if (m_private_key == null)
                return null;
            if (m_cert == null)
                return null;
            if (m_cert.Details.IsCA)
            {
                byte[] tempKey = new byte[m_private_key.Length + m_cert.Details.PublicKey.Length];
                m_private_key.CopyTo(tempKey, 0);
                m_cert.Details.PublicKey.CopyTo(tempKey, m_private_key.Length);

                return CPEM.FromBytes(tempKey, c_NebulaCAKeyID)?.PEM;
            }
            else
            {
                return CPEM.FromBytes(m_private_key, c_NebulaKeyID)?.PEM;
            }
        }
        //-----------------------------------------------------------------------
        public DateTime? GetStartDate()
        {
            if (m_cert == null)
                return null;
            else
                return new DateTime(1970, 1, 1).Add(TimeSpan.FromSeconds(m_cert.Details.NotBefore));
        }
        //-----------------------------------------------------------------------
        public DateTime? GetEndDate()
        {
            if (m_cert == null)
                return null;
            else
                return new DateTime(1970, 1, 1).Add(TimeSpan.FromSeconds(m_cert.Details.NotAfter));
        }
        //-----------------------------------------------------------------------
        public IPAddress? GetIPAddress()
        {
            if (m_cert == null)
                return null;

            if (m_cert.Details.Ips.Count != 2)
                return null;

            return IPNetwork.ToIPAddress(m_cert.Details.Ips[0], System.Net.Sockets.AddressFamily.InterNetwork);
        }
        //-----------------------------------------------------------------------
        public IPAddress? GetIPMask()
        {
            if (m_cert == null)
                return null;

            if (m_cert.Details.Ips.Count != 2)
                return null;

            return IPNetwork.ToIPAddress(m_cert.Details.Ips[1], System.Net.Sockets.AddressFamily.InterNetwork);
        }
        //-----------------------------------------------------------------------
        public bool IsExpired()
        {
            if (m_cert == null)
                return true;

            if (GetStartDate() > GetEndDate())
                return true;
            if (GetStartDate() > DateTime.UtcNow)
                return true;
            if (DateTime.UtcNow > GetEndDate())
                return true;

            return false;
        }
        //-----------------------------------------------------------------------
        public bool IsSignatureValid(in CNebulaCert inSigner)
        {
            if (inSigner == null)
                return false;
            if (inSigner.m_private_key != null)
            {
                if (!inSigner.IsValidCA())
                    return false;
            }
            else
            {
                if (inSigner.IsExpired())
                    return false;
            }
            if (IsExpired())
                return false;
            if (m_cert == null)
                return false;
            if (m_cert.Details.IsCA)
                return false;

            //-----check issuer
            byte[] s0 = m_cert.Details.Issuer.ToByteArray();
            byte[]? s1 = inSigner.GetSHA256();
            if (s1 == null)
                return false;

            if (s0.Length != s1.Length)
                return false;
            for (int i = 0; i < s0.Length; i++)
                if (s0[i] != s1[i])
                    return false;

            //-----check signature
            if (inSigner.m_cert == null)
                return false;
            byte[] pubKeyBytes = inSigner.m_cert.Details.PublicKey.ToByteArray();
            if (pubKeyBytes.Length != Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters.KeySize)
                return false;
            var pubKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(pubKeyBytes);

            Org.BouncyCastle.Crypto.ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner("Ed25519");
            signer.Init(false, pubKey);

            byte[] msg = new byte[m_cert.Details.CalculateSize()];
            m_cert.Details.WriteTo(new Google.Protobuf.CodedOutputStream(msg));

            if (m_cert.Details.NotBefore < inSigner.m_cert.Details.NotBefore)
                return false;
            if (m_cert.Details.NotAfter >= inSigner.m_cert.Details.NotAfter)
                return false;

            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.VerifySignature(m_cert.Signature.ToByteArray());
        }
        //-----------------------------------------------------------------------
        public bool IsValidCA()
        {
            if (m_cert == null)
                return false;
            if (m_private_key == null)
                return false;
            if (!m_cert.Details.IsCA)
                return false;
            if (m_cert.Details.Issuer.Length > 0)
                return false;
            if (IsExpired())
                return false;

            byte[]? sig = GetSignature(m_cert.Details, new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(m_private_key));
            if (sig == null)
                return false;

            if (sig.Length != m_cert.Signature.Length)
                return false;
            for (int i = 0; i < sig.Length; i++)
                if (sig[i] != m_cert.Signature[i])
                    return false;

            return true;
        }
        //-----------------------------------------------------------------------
        //-----------------------------------------------------------------------
        byte[]? GetSHA256()
        {
            if (m_cert == null)
                return null;
            byte[] cert_bytes = new byte[m_cert.CalculateSize()];
            m_cert.WriteTo(new Google.Protobuf.CodedOutputStream(cert_bytes));

            Org.BouncyCastle.Crypto.Digests.Sha256Digest myHash = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
            myHash.BlockUpdate(cert_bytes, 0, cert_bytes.Length);
            byte[] compArr = new byte[myHash.GetDigestSize()];
            myHash.DoFinal(compArr, 0);

            return compArr;
        }
        //-----------------------------------------------------------------------
        static Google.Protobuf.ByteString? GetPBSig(RawNebulaCertificateDetails inDetails, Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters key)
        {
            if (inDetails == null)
                return null;
            byte[]? sig = GetSignature(inDetails, key);
            if (sig == null)
                return null;
            return Google.Protobuf.ByteString.CopyFrom(sig);
        }
        //-----------------------------------------------------------------------
        static byte[]? GetSignature(RawNebulaCertificateDetails inDetails, Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters key)
        {
            if (inDetails == null)
                return null;
            if (key == null)
                return null;

            byte[] cert_details_bytes = new byte[inDetails.CalculateSize()];
            inDetails.WriteTo(new Google.Protobuf.CodedOutputStream(cert_details_bytes));

            Org.BouncyCastle.Crypto.ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner("Ed25519");
            signer.Init(true, key);
            signer.BlockUpdate(cert_details_bytes, 0, cert_details_bytes.Length);
            return signer.GenerateSignature();
        }
        //-----------------------------------------------------------------------
    }
}
