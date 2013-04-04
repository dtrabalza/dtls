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
package org.spongycastle.crypto.dtls.core;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;
import java.util.logging.Logger;

import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;
import org.spongycastle.crypto.dtls.exceptions.SignatureNotValidException;

public class DTLSSigner {
	
	private static final Logger LOG = Logger.getLogger(DTLSSigner.class.getName());

	/**
	 * This method signs the data in dataToBeSigned with the method
	 * in signatureMethod, the private key in signingKey and returns
	 * a byte array containing the signature
	 * @param signatureMethod
	 * @param signingKey
	 * @param dataToBeSigned
	 * @return
	 */
	public static byte[] sign(String signatureMethod, PrivateKey signingKey,
			byte[] dataToBeSigned) {

		try {
			Signature dsa;
		
			dsa = Signature.getInstance(signatureMethod);
		
			System.out.println("Signing with key: " + signingKey);
			dsa.initSign(signingKey);
			dsa.update(dataToBeSigned);
		
			return dsa.sign();
		} catch (Exception e) {
			System.out.println("Signing problem; aborting");
			return null;
		}
		
	}

	/**
	 * This method verifies a signature given signatureMethod, the public key
	 * correspondent to the private key used for signing, the data that has been
	 * signed and their signature 
	 * @param signatureMethod
	 * @param publicKey
	 * @param data
	 * @param signature
	 * @return
	 * @throws SignatureNotValidException
	 */
	public static boolean verifySignature(String signatureMethod, PublicKey publicKey,
			List<byte[]> data, byte[] signature) throws ProgramErrorException {
		try {
			Signature dsa = Signature.getInstance(signatureMethod);
			
			//initialize verifier
			dsa.initVerify(publicKey);
			
			//getting the parameters to verify
			for (byte[] b : data) {
				dsa.update(b);
			}
			return dsa.verify(signature);
			
		} catch (Exception e) {
			LOG.severe("Signing problem; aborting");
			throw new ProgramErrorException("Unable to verify the signature");
		}
	}

}
