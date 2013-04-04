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
package org.spongycastle.crypto.dtls.core.keyExchange;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.logging.Logger;

import org.spongycastle.crypto.dtls.core.DTLSProtocolHandler;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.ServerKeyExchangeAlgorithm;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;
import org.spongycastle.crypto.tls.ECCurveType;
import org.spongycastle.crypto.tls.NamedCurve;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.asymmetric.ec.KeyPairGenerator;

public class ECDHEKeyExchange implements DTLSKeyExchange {
	
	private static final Logger LOG = Logger.getLogger(ECDHEKeyExchange.class.getName());

	/*
	 * key pair generated from the negotiated curve 
	 * that must be one of the proposed ones by the client 
	 */
	private KeyPair kp;

	public ECDHEKeyExchange(DTLSContext context) {
    	//TODO: take the curve name dynamically from the context
		
		try {
			ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
			
    		KeyPairGenerator g = new KeyPairGenerator.ECDH();
    		
			g.initialize(ecGenSpec, new SecureRandom());
			kp = g.generateKeyPair();
			
		} catch (InvalidAlgorithmParameterException e) {
			// TODO raise exception
			e.printStackTrace();
		}
    	
	}

	/**
	 * Creates and returns a server key exchange message
	 * according to RFC 4492 5.4
	 */
	@Override
	public ServerKeyExchangeAlgorithm getServerKeyExchange(DTLSContext context) {
		/**
		 * ServerKeyExchange{
		 * 	
		 * 	ServerECDHParams{
		 * 		ECParameters{
		 * 			ECCurveType    curve_type;
		 * 			NamedCurve named_curve;
		 * 		}
		 * 		ECPoint public;
		 * 	}
		 * 	Signature signed_params(clientRandom + serverRandom + ServerECDHParams);
		 * }
		 */
		try {

			ECParameters ecParameters = new ECParameters(ECCurveType.named_curve, NamedCurve.secp256r1);
			
			ServerECDHParams serverECDHParams = new ServerECDHParams(ecParameters);
			
			ECPublicKey ecPKey = (ECPublicKey)kp.getPublic();
			serverECDHParams.setEcPoint(ecPKey.getQ().getEncoded());
			
			byte[] dataToSign = parseDataSign(serverECDHParams);
			
			LOG.fine("Preparing to sign the following data: " + DTLSUtils.getHexString(dataToSign));
		
			//signature of the ServerECDHParams
			byte[] signature = null;

			//signature
			Signature dsa = Signature.getInstance("SHA1withECDSA");
			LOG.fine("Private key for signing: " + (PrivateKey) context.getSigningKey());
			dsa.initSign((PrivateKey) context.getSigningKey()); 	//sign with the server's private key
			
			//adding bytes for signature
			dsa.update(context.getSecurityParameters().getClientRandom());
			dsa.update(context.getSecurityParameters().getServerRandom());
			dsa.update(dataToSign);
			
			//signing
			signature = dsa.sign();
			
			LOG.fine("Signature: " + DTLSUtils.getHexString(signature));
			
			//make dynamic
			EC_DIFFIE_HELLMAN ecdh = new EC_DIFFIE_HELLMAN(serverECDHParams, signature);			
				
//			//setting the signature length
//			signatureLength = signature.length;
			
//			byte[] keyExchange = DTLSUtils.concat(dataToSign, DTLSUtils.getBytesFromValue(signatureLength, 2));
//			keyExchange = DTLSUtils.concat(keyExchange, signature);
			
			//everything ok, returning the key exchange
			return ecdh;
		
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
	}

	public static byte[] parseDataSign(ServerECDHParams serverECDHParams) {
		byte curve_type = (byte)serverECDHParams.getCurve_params().getCurve_type();
		byte[] named_curve = DTLSUtils.getBytesFromValue(serverECDHParams.getCurve_params().getNamedCurve(), 2);
		//2  bytes length
		int ecPointLength;
		byte[] ecPoint = serverECDHParams.getEcPoint();
		
		ecPointLength = ecPoint.length;
//			//2  bytes length
//			int signatureLength;
		
		byte[] dataToSign = DTLSUtils.concat(new byte[]{curve_type}, named_curve);
		dataToSign = DTLSUtils.concat(dataToSign, DTLSUtils.getBytesFromValue(ecPointLength, 1));
		dataToSign = DTLSUtils.concat(dataToSign, ecPoint);
		return dataToSign;
	}
	
	/**
	 * RFC 4492 5.7
	 */
	@Override
	public byte[] getClientKeyExchange(DTLSContext context) {
		ECPublicKey ecPKey = (ECPublicKey)kp.getPublic();
		return ecPKey.getQ().getEncoded();
//		return /*Base64.encode(*/kp.getPublic().getEncoded();
	}

	public KeyPair getKp() {
		return kp;
	}

	public void setKp(KeyPair kp) {
		this.kp = kp;
	}
	
}
