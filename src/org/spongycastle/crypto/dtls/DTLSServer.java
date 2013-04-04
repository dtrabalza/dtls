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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;

import org.spongycastle.crypto.dtls.core.DTLSProtocolHandler;
import org.spongycastle.crypto.dtls.core.context.DTLSECCContext;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class DTLSServer implements DTLSConnector {

	/*
	 * SERVER CERTIFICATE
	 */
	// type of trust store
	private static final String SERVER_CERT_STORE_TYPE = "BKS";
	// Path to the trust store
	private static final String SERVER_CERT_STORE_FILE_PATH = "/server.jks";
	// Password to load the trust store
	private static final char[] SERVER_CERT_STORE_PASSWORD = "serverPassword"
			.toCharArray();

	/*
	 * TRUST STORE TO VALIDATE THE CLIENT FOR MUTUAL AUTH
	 */
	// type of trust store
	private static final String TRUST_STORE_TYPE = "BKS";
	// Path to the trust store
	private static final String TRUST_STORE_FILE_PATH = "/trustStore.jks";
	// Password to load the trust store
	private static final char[] TRUST_STORE_PASSWORD = "trustPassword"
			.toCharArray();

	/**
	 * SERVER PRIVATE KEY FOR SIGNING
	 */
	// type of key store
	private static final String KEY_STORE_TYPE = "PKCS12";
	// Path to the key store
	private static final String KEY_STORE_FILE_PATH = "/server.p12";
	// Password to load the key store
	private static final char[] KEY_STORE_PASSWORD = "serverPassword"
			.toCharArray();

	DTLSContext context;

	final DTLSProtocolHandler handler;

	public DTLSServer() throws UnrecoverableKeyException, KeyStoreException,
			NoSuchProviderException, NoSuchAlgorithmException,
			CertificateException, IOException {
		context = loadECCContext();

		handler = new DTLSProtocolHandler(4433, context, false);

		handler.registerSubscriber(this);

		handler.setMutualAuth(true);
		
	}

	public void sendData(byte[] data) throws IOException {
		handler.send(data);
	}

	@Override
	public void DataReceived(Object sender, Object value) {
		byte[] data = (byte[]) value;
		System.out.println("DATA RECEIVED FROM CLIENT " + new String(data));
		
		try {
			handler.send(new String("Response @ " + new Date().toString()).getBytes());
		} catch (IOException e) {
			System.out.println("Impossible to send response to the client");
		}
	}

	/**
	 * @param args
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 */
	public static void main(String[] args) throws UnrecoverableKeyException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);

		new DTLSServer();

//		client.sendData(new String("Client sent DTLS-Protected data!!!").getBytes());

	}

	private DTLSContext loadECCContext() throws KeyStoreException,
			NoSuchProviderException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException {

		// load key store
		KeyStore serverStore = KeyStore.getInstance(SERVER_CERT_STORE_TYPE);// ,
																			// PROVIDER);
		// open the trust store
		InputStream trustIn = new FileInputStream(new File(new File("")
				.getAbsolutePath().toString(), SERVER_CERT_STORE_FILE_PATH));
		serverStore.load(trustIn, SERVER_CERT_STORE_PASSWORD);

		// load key store
		KeyStore trustStore = KeyStore.getInstance(TRUST_STORE_TYPE);// ,
																		// PROVIDER);
		// open the trust store
		trustIn = new FileInputStream(new File(new File("").getAbsolutePath()
				.toString(), TRUST_STORE_FILE_PATH));
		trustStore.load(trustIn, TRUST_STORE_PASSWORD);

		// load the key store
		KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);// , PROVIDER);
		// open the key store
		InputStream keyIn = new FileInputStream(new File(new File("")
				.getAbsolutePath().toString(), KEY_STORE_FILE_PATH));
		keyStore.load(keyIn, KEY_STORE_PASSWORD);

		DTLSECCContext context = new DTLSECCContext();

		context.setServerChain(serverStore.getCertificateChain("server"));

		context.setTrustStore(trustStore.getCertificateChain("server"));

		context.setSigningKey(keyStore.getKey("server",
				"serverPassword".toCharArray()));

		return context;
	}

}
