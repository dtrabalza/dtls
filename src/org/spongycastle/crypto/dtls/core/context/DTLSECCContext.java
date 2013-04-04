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
package org.spongycastle.crypto.dtls.core.context;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;

import org.spongycastle.crypto.dtls.constants.ClientCertificateType;
import org.spongycastle.crypto.dtls.constants.HashAlgorithm;
import org.spongycastle.crypto.dtls.constants.SignatureAlgorithm;
import org.spongycastle.crypto.dtls.core.DTLSSigner;
import org.spongycastle.crypto.dtls.core.handshake.DistinguishedName;
import org.spongycastle.crypto.dtls.core.handshake.SignatureAndHashAlgorithm;
import org.spongycastle.crypto.dtls.core.keyExchange.ECDHEKeyExchange;
import org.spongycastle.crypto.dtls.core.keyExchange.EC_DIFFIE_HELLMAN;
import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;
import org.spongycastle.crypto.dtls.exceptions.SignatureNotValidException;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.ServerKeyExchangeAlgorithm;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;


/**
 * Context for Elliptic Curve cipher suites
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class DTLSECCContext extends DTLSAbstractContext implements DTLSContext{

	//Server's certificate
	private Certificate[] serverChain;
	
	//client trusted certificates to validate the server
	private Certificate[] trustCertificateChain;
	
	private Key signingKey;

	private List<X509Certificate> receivedCerts;
	
	public DTLSECCContext() {
		super.init(null);
	}
	
	public Certificate[] getServerChain() {
		return serverChain;
	}

	/**
	 * This methods returns the signature algorithms supported by the server
	 * and that the client must use to send the certificate in the next flight
	 * @return
	 */
	public short[] getClientCertificateTypes() {
		return new short[] {
			ClientCertificateType.ecdsa_sign
		};
	}
	
	/**
	 * This method returns the available signature and hash algorithms by the
	 * server that the client can use to send its certificate
	 * @return
	 */
	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
		ArrayList<SignatureAndHashAlgorithm> alg = new ArrayList<SignatureAndHashAlgorithm>();

		alg.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
		
		return alg;
	}
	
	public List<DistinguishedName> getValidDN(){
		ArrayList<DistinguishedName> distinguishedNames = new ArrayList<DistinguishedName>();
		//get valid DN
		if (serverChain != null && serverChain[0] != null){
			String dn = ((X509Certificate)serverChain[0]).getSubjectDN().getName();
			distinguishedNames.add(new DistinguishedName(dn.getBytes()));
			return distinguishedNames;
		}else
			return null;
	}

	/**
	 * The server certificate to be authenticated by the client
	 * @param certificateChain
	 */
	public void setServerChain(Certificate[] certificateChain) {
		this.serverChain = certificateChain;
	}

	/**
	 * This is the chain that the client uses to verify the server's
	 * certificate
	 * @param certificates
	 */
	public void setTrustStore(Certificate[] certificates) {
		this.trustCertificateChain = certificates;
	}

	/**
	 * This is the chain that the client uses to verify the server's
	 * certificate
	 */
	public Certificate[] getTrustAnchors() {
		return trustCertificateChain;
	}
	
	public Key getSigningKey(){
		return this.signingKey;
	}

	public void setSigningKey(Key key) {
		this.signingKey = key;
	}
	
	/**
	 * TODO: check coupling
	 * @throws SignatureNotValidException 
	 * @throws ProgramErrorException 
	 */
	public void verifyServerKeyExchange(ServerKeyExchangeAlgorithm keyExchange) throws ProgramErrorException, SignatureNotValidException{
		try {
			if (keyExchange instanceof EC_DIFFIE_HELLMAN){
				//verify signature

				Certificate cert = receivedCerts.get(0);

				//getting the parameters to verify
				byte[] signedParameters = ECDHEKeyExchange.parseDataSign(((EC_DIFFIE_HELLMAN) keyExchange).getParams());
				
				List<byte[]> data = new ArrayList<byte[]>();
				data.add(securityParameters.getClientRandom());
				data.add(securityParameters.getServerRandom());
				data.add(signedParameters);
				
				byte[] signature = ((EC_DIFFIE_HELLMAN) keyExchange).getSignature();
				
				boolean signatureVerified = DTLSSigner.verifySignature("SHA1withECDSA", cert.getPublicKey(), 
						data , signature);

				//verification
				if (signatureVerified){
					System.out.println("Signature Verified!!!!");
				}else{
		        	System.out.println("Signature FAILED.");
		        	throw new SignatureNotValidException();
				}
				
				//calculate the the shared secret
				PublicKey pubKey = decodePublicKey(((EC_DIFFIE_HELLMAN) keyExchange).getParams().getEcPoint());
				
				KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		    	ka.init(this.keyExchange.getKp().getPrivate());
		    	ka.doPhase(pubKey, true);
		    	
		    	this.preMasterSecret = ka.generateSecret();
		    	LOG.info("Generated PreMasterSecret from ECDHE with value: " +
		    			DTLSUtils.getHexString(preMasterSecret));
			}
		}catch (NoSuchAlgorithmException e) {
			throw new ProgramErrorException("Key agreement Algorithm not supported. " + e);
		} catch (InvalidKeyException e) {
			throw new ProgramErrorException("Key not valid during key agreement. " + e);
		}
	}

	public void setReceivedCertificates(List<X509Certificate> certificates) {
		this.receivedCerts = certificates;
	}

	/**
	 * It is assumed that the end-user certificate (client) is the first in the list;
	 * @return
	 */
	public java.security.cert.Certificate getClientCertificate() {
		return trustCertificateChain[0];
	}

	public List<X509Certificate> getReceivedCerts() {
		return receivedCerts;
	}

	public void setReceivedCerts(List<X509Certificate> receivedCerts) {
		this.receivedCerts = receivedCerts;
	}
	
}
