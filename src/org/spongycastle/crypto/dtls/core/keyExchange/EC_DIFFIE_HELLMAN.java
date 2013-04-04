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

import org.spongycastle.crypto.dtls.interfaces.ServerKeyExchangeAlgorithm;

public class EC_DIFFIE_HELLMAN implements ServerKeyExchangeAlgorithm{

	// ec parameters
	private ServerECDHParams params;

	//2  bytes length
	int signatureLength;
	
	// opaque signature
	private byte[] signature;

	public EC_DIFFIE_HELLMAN(ServerECDHParams serverECDHParams, byte[] signature) {
		this.params = serverECDHParams;
		setSignature(signature);
	}

	public EC_DIFFIE_HELLMAN() {

	}

	public ServerECDHParams getParams() {
		return params;
	}

	public void setParams(ServerECDHParams params) {
		this.params = params;
	}

	public byte[] getSignature() {
		return signature;
	}

	public void setSignatureLength(int signatureLength) {
		this.signatureLength = signatureLength;
	}

	//setting length
	public void setSignature(byte[] signature) {
		this.signature = signature;
		this.signatureLength = signature.length;
	}

	public int getTotalByteLength() {
		int result = 0;
		result += params.getTotalByteLength();
		result += 2;	//static length
		result += signatureLength;
		return result;
	}

	public int getSignatureLength() {
		return signatureLength;
	}
	
}
