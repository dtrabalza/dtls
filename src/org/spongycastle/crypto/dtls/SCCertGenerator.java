/**
 * The Bouncy Castle License
 *
 * Copyright (c) 2000-2012 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * 
 * @author Daniele Trabalza <daniele@sics.se> 
 * SICS - Swedish Institute of Computer Science
 * Stockholm, Sweden
 */
package org.spongycastle.crypto.dtls;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import security.auth.x500.X500PrivateCredential;

public class SCCertGenerator {
	
	private static final String KEY_STORE_TYPE = "BKS";

	/**
	 * Names and passwords for the key store entries
	 */
	private static final String SERVER_NAME = "server";
	private static final char[] SERVER_PASSWORD = "serverPassword"
			.toCharArray();

	private static final String CLIENT_NAME = "client";
	private static final char[] CLIENT_PASSWORD = "clientPassword"
			.toCharArray();

	private static final String TRUST_STORE_NAME = "trustStore";
	private static final char[] TRUST_STORE_PASSWORD = "trustPassword"
			.toCharArray();

	private static char[] KEY_PASSWD = "keyPassword".toCharArray();

	private static String ROOT_ALIAS = "root";
	private static String INTERMEDIATE_ALIAS = "intermediate";
	private static String END_ENTITY_ALIAS = "end";

	private static final int VALIDITY_PERIOD = 365; // one year

	public SCCertGenerator() {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

	// /**
	// * Create a KeyStore containing the a private credential with
	// * certificate chain and a trust anchor.
	// */
	// private KeyStore createCredentials()
	// throws Exception
	// {
	// KeyStore store = KeyStore.getInstance("JKS");
	//
	// store.load(null, null);
	//
	// X500PrivateCredential rootCredential = createRootCredential();
	// X500PrivateCredential interCredential =
	// createIntermediateCredential(rootCredential.getPrivateKey(),
	// rootCredential.getCertificate());
	// X500PrivateCredential endCredential =
	// createEndEntityCredential(interCredential.getPrivateKey(),
	// interCredential.getCertificate());
	//
	// store.setCertificateEntry(rootCredential.getAlias(),
	// rootCredential.getCertificate());
	// store.setKeyEntry(endCredential.getAlias(),
	// endCredential.getPrivateKey(), KEY_PASSWD,
	// new Certificate[] { endCredential.getCertificate(),
	// interCredential.getCertificate(), rootCredential.getCertificate() });
	//
	// return store;
	// }

	/**
	 * Generate a X500PrivateCredential for the root entity.
	 */
	private X500PrivateCredential createRootCredential() throws Exception {
		// Generate key pair for the root certificate
		KeyPair rootPair = generateECDSAKeyPair();
		// creating and selfsigning the certificate
		X509Certificate rootCert = makeCertificate(rootPair.getPublic(),
				"CN=Root Certificate", rootPair.getPrivate(),
				"CN=Root Certificate");

		return new X500PrivateCredential(rootCert, rootPair.getPrivate(),
				ROOT_ALIAS);
	}

	/**
	 * Generate a X500PrivateCredential for the intermediate entity.
	 */
	private X500PrivateCredential createIntermediateCredential(
			PrivateKey caKey, X509Certificate caCert) throws Exception {
		KeyPair interPair = generateECDSAKeyPair();
		X509Certificate interCert = makeCertificate(interPair.getPublic(),
				"CN=Intermediate Certificate", caKey, caCert
						.getSubjectX500Principal().toString());

		return new X500PrivateCredential(interCert, interPair.getPrivate(),
				INTERMEDIATE_ALIAS);
	}

	/**
	 * Generate a X500PrivateCredential for the end entity.
	 */
	private X500PrivateCredential createEndEntityCredential(PrivateKey caKey,
			X509Certificate caCert) throws Exception {
		KeyPair endPair = generateECDSAKeyPair();
		// X509Certificate endCert = generateEndEntityCert(endPair.getPublic(),
		// caKey, caCert);
		X509Certificate endCert = makeCertificate(endPair.getPublic(),
				"DN=End Certificate", caKey, caCert.getSubjectX500Principal()
						.toString());

		return new X500PrivateCredential(endCert, endPair.getPrivate(),
				END_ENTITY_ALIAS);
	}

	/**
	 * This method returns a certificate based on the parameters specified.
	 * 
	 * Note: in the case of root CA, the singnerCA is the private key (that is
	 * the couple of the private key in the certificate), and the DN is the
	 * same.
	 * 
	 * @param pubKeyOfDN
	 *            The public key to be bind with the distinguished name
	 * @param subDN
	 *            The distinguished name to be bind with the public key
	 * @param signerCA
	 *            The private key of the issuer that signs the certificate
	 * @param caDN
	 *            The distinguished name of the CA that signs the certificate
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws OperatorCreationException
	 */
	private X509Certificate makeCertificate(PublicKey pubKeyOfDN, String subDN,
			PrivateKey signerCA, String caDN) throws GeneralSecurityException,
			IOException, OperatorCreationException {
		
		//setting the date
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DAY_OF_WEEK, VALIDITY_PERIOD);
		
//		System.out.println("Expiration date = " + new Date(cal.getTimeInMillis()));

		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
				new X500Name(caDN), BigInteger.valueOf(System
						.currentTimeMillis()),
				new Date(System.currentTimeMillis()),
				// new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 *
				// 100)),
				new Date(cal.getTimeInMillis()),
				new X500Name(subDN), pubKeyOfDN);

		// v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false,
		// createSubjectKeyId(subPub));
		//
		// v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
		// createAuthorityKeyId(issPub));

		return new JcaX509CertificateConverter().setProvider(
				BouncyCastleProvider.PROVIDER_NAME).getCertificate(
				v3CertGen.build(new JcaContentSignerBuilder("SHA1withECDSA")
						.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
								signerCA)));
	}

	/**
	 * Create a random 1024 bit RSA key pair
	 */
	private KeyPair generateECDSAKeyPair() throws Exception {

		ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");

//		System.out.println(ecGenSpec.getName());

		KeyPairGenerator g = new KeyPairGenerator.ECDSA();

		g.initialize(ecGenSpec, new SecureRandom());

		KeyPair pair = g.generateKeyPair();

		return pair;
	}

	public void createKeyStores(String storageDir) throws Exception {
		X500PrivateCredential rootCredential = createRootCredential();
		X500PrivateCredential interCredential = createIntermediateCredential(
				rootCredential.getPrivateKey(), rootCredential.getCertificate());
		X500PrivateCredential endCredential = createEndEntityCredential(
				interCredential.getPrivateKey(),
				interCredential.getCertificate());

		// client credentials
		KeyStore keyStore = KeyStore.getInstance("PKCS12", "SC");

		// creation of the keystore
		keyStore.load(null, null);

		keyStore.setKeyEntry(
				CLIENT_NAME,
				endCredential.getPrivateKey(),
				CLIENT_PASSWORD,
				new Certificate[] { endCredential.getCertificate(),
						interCredential.getCertificate(),
						rootCredential.getCertificate() });

		System.out.println("Saving client private key in " + storageDir + "/" +  CLIENT_NAME + ".p12");
		keyStore.store(new FileOutputStream(storageDir + "/" +  CLIENT_NAME + ".p12"),
				CLIENT_PASSWORD);
		
		//server private key for signing
		keyStore = KeyStore.getInstance("PKCS12", "SC");
		
		// creation of the keystore
		keyStore.load(null, null);
		
		keyStore.setKeyEntry(
				SERVER_NAME,
				rootCredential.getPrivateKey(),
				SERVER_PASSWORD,
				new Certificate[] { rootCredential.getCertificate() });
		
		System.out.println("Saving server private key in " + storageDir + "/" +  SERVER_NAME + ".p12");
		keyStore.store(new FileOutputStream(storageDir + "/" +  SERVER_NAME + ".p12"),
				SERVER_PASSWORD);
		
		// trust store for client
		keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
		
		// creation of the keystore
		keyStore.load(null, null);

		keyStore.setCertificateEntry(SERVER_NAME,
				rootCredential.getCertificate());
		
		// added by me
		keyStore.setKeyEntry(
				SERVER_NAME,
				endCredential.getPrivateKey(),
				CLIENT_PASSWORD,
				new Certificate[] { endCredential.getCertificate(),
						interCredential.getCertificate(),
						rootCredential.getCertificate() });

		System.out.println("Saving truststore in " + storageDir + "/" +  TRUST_STORE_NAME + ".jks");
		keyStore.store(new FileOutputStream(storageDir + "/" +  TRUST_STORE_NAME
				+ ".jks"), TRUST_STORE_PASSWORD);

		// server credentials
		keyStore = KeyStore.getInstance(KEY_STORE_TYPE);

		keyStore.load(null, null);

		keyStore.setKeyEntry(SERVER_NAME, rootCredential.getPrivateKey(),
				SERVER_PASSWORD,
				new Certificate[] { rootCredential.getCertificate() });

		System.out.println("Saving server keystore in " + storageDir + "/" +  SERVER_NAME + ".jks");
		keyStore.store(new FileOutputStream(storageDir + "/" +  SERVER_NAME + ".jks"),
				SERVER_PASSWORD);

	}

	public static void main(String[] args) throws Exception {
		SCCertGenerator gen = new SCCertGenerator();
		File loc = new File("");
		System.out.println("Creating certs in: " + loc.getAbsolutePath().toString());
		gen.createKeyStores(loc.getAbsolutePath().toString());
	}

}
