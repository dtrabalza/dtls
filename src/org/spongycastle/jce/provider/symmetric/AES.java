package org.spongycastle.jce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

import javax.crypto.spec.IvParameterSpec;

import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.engines.AESWrapEngine;
import org.spongycastle.crypto.engines.RFC3211WrapEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.modes.CFBBlockCipher;
import org.spongycastle.crypto.modes.OFBBlockCipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.JCEBlockCipher;
import org.spongycastle.jce.provider.JCEKeyGenerator;
import org.spongycastle.jce.provider.JCEMac;
import org.spongycastle.jce.provider.JDKAlgorithmParameterGenerator;
import org.spongycastle.jce.provider.JDKAlgorithmParameters;
import org.spongycastle.jce.provider.WrapCipherSpi;

public final class AES
{
    private AES()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new AESFastEngine());
        }
    }

    public static class CBC
       extends JCEBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new AESFastEngine()), 128);
        }
    }

    static public class CFB
        extends JCEBlockCipher
    {
        public CFB()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new AESFastEngine(), 128)), 128);
        }
    }

    static public class OFB
        extends JCEBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new AESFastEngine(), 128)), 128);
        }
    }

    public static class AESCMAC
        extends JCEMac
    {
        public AESCMAC()
        {
            super(new CMac(new AESFastEngine()));
        }
    }

    static public class Wrap
        extends WrapCipherSpi
    {
        public Wrap()
        {
            super(new AESWrapEngine());
        }
    }

    public static class RFC3211Wrap
        extends WrapCipherSpi
    {
        public RFC3211Wrap()
        {
            super(new RFC3211WrapEngine(new AESFastEngine()), 16);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            this(192);
        }

        public KeyGen(int keySize)
        {
            super("AES", keySize, new CipherKeyGenerator());
        }
    }

    public static class KeyGen128
        extends KeyGen
    {
        public KeyGen128()
        {
            super(128);
        }
    }

    public static class KeyGen192
        extends KeyGen
    {
        public KeyGen192()
        {
            super(192);
        }
    }

    public static class KeyGen256
        extends KeyGen
    {
        public KeyGen256()
        {
            super(256);
        }
    }

    public static class AlgParamGen
        extends JDKAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for AES parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[]  iv = new byte[16];

            if (random == null)
            {
                random = new SecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParams
        extends JDKAlgorithmParameters.IVAlgorithmParameters
    {
        protected String engineToString()
        {
            return "AES IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        /**
         * These three got introduced in some messages as a result of a typo in an
         * early document. We don't produce anything using these OID values, but we'll
         * read them.
         */
        private static final String wrongAES128 = "2.16.840.1.101.3.4.2";
        private static final String wrongAES192 = "2.16.840.1.101.3.4.22";
        private static final String wrongAES256 = "2.16.840.1.101.3.4.42";

        public Mappings()
        {
            put("AlgorithmParameters.AES", "org.spongycastle.jce.provider.symmetric.AES$AlgParams");
            put("Alg.Alias.AlgorithmParameters." + wrongAES128, "AES");
            put("Alg.Alias.AlgorithmParameters." + wrongAES192, "AES");
            put("Alg.Alias.AlgorithmParameters." + wrongAES256, "AES");
            put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
            put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
            put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes256_CBC, "AES");

            put("AlgorithmParameterGenerator.AES", "org.spongycastle.jce.provider.symmetric.AES$AlgParamGen");
            put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES128, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES192, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES256, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes256_CBC, "AES");

            put("Cipher.AES", "org.spongycastle.jce.provider.symmetric.AES$ECB");
            put("Alg.Alias.Cipher." + wrongAES128, "AES");
            put("Alg.Alias.Cipher." + wrongAES192, "AES");
            put("Alg.Alias.Cipher." + wrongAES256, "AES");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_ECB, "org.spongycastle.jce.provider.symmetric.AES$ECB");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_ECB, "org.spongycastle.jce.provider.symmetric.AES$ECB");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_ECB, "org.spongycastle.jce.provider.symmetric.AES$ECB");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_CBC, "org.spongycastle.jce.provider.symmetric.AES$CBC");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_CBC, "org.spongycastle.jce.provider.symmetric.AES$CBC");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_CBC, "org.spongycastle.jce.provider.symmetric.AES$CBC");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_OFB, "org.spongycastle.jce.provider.symmetric.AES$OFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_OFB, "org.spongycastle.jce.provider.symmetric.AES$OFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_OFB, "org.spongycastle.jce.provider.symmetric.AES$OFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_CFB, "org.spongycastle.jce.provider.symmetric.AES$CFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_CFB, "org.spongycastle.jce.provider.symmetric.AES$CFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_CFB, "org.spongycastle.jce.provider.symmetric.AES$CFB");
            put("Cipher.AESWRAP", "org.spongycastle.jce.provider.symmetric.AES$Wrap");
            put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes128_wrap, "AESWRAP");
            put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes192_wrap, "AESWRAP");
            put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes256_wrap, "AESWRAP");
            put("Cipher.AESRFC3211WRAP", "org.spongycastle.jce.provider.symmetric.AES$RFC3211Wrap");

            put("KeyGenerator.AES", "org.spongycastle.jce.provider.symmetric.AES$KeyGen");
            put("KeyGenerator.2.16.840.1.101.3.4.2", "org.spongycastle.jce.provider.symmetric.AES$KeyGen128");
            put("KeyGenerator.2.16.840.1.101.3.4.22", "org.spongycastle.jce.provider.symmetric.AES$KeyGen192");
            put("KeyGenerator.2.16.840.1.101.3.4.42", "org.spongycastle.jce.provider.symmetric.AES$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_ECB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CBC, "org.spongycastle.jce.provider.symmetric.AES$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_OFB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CFB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_ECB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CBC, "org.spongycastle.jce.provider.symmetric.AES$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_OFB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CFB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_ECB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CBC, "org.spongycastle.jce.provider.symmetric.AES$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_OFB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CFB, "org.spongycastle.jce.provider.symmetric.AES$KeyGen256");
            put("KeyGenerator.AESWRAP", "org.spongycastle.jce.provider.symmetric.AES$KeyGen");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_wrap, "org.spongycastle.jce.provider.symmetric.AES$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_wrap, "org.spongycastle.jce.provider.symmetric.AES$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_wrap, "org.spongycastle.jce.provider.symmetric.AES$KeyGen256");

            put("Mac.AESCMAC", "org.spongycastle.jce.provider.symmetric.AES$AESCMAC");
        }
    }
}
