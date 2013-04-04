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
package org.spongycastle.crypto.dtls.core.handshake;

import org.spongycastle.crypto.dtls.constants.HashAlgorithm;
import org.spongycastle.crypto.dtls.constants.SignatureAlgorithm;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;

public class CertificateVerify implements HandshakeMessage {
	
	// 2 bytes total
	private SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	// 2 bytes length
	private int length;

	private byte[] signatureOfMessagesHash;

	public static HandshakeMessage newCertificateVerify() {
		CertificateVerify certificateVerify = new CertificateVerify();
		
		//TODO: make dynamic
		certificateVerify.setSignatureAndHashAlgorithm(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
		
		/*
		 * Signature updated later because it needs the
		 * hashes of the messages and some fields are 
		 * set in the end of the preparing state
		 */
		return certificateVerify;
	}

	public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
		return signatureAndHashAlgorithm;
	}



	public void setSignatureAndHashAlgorithm(
			SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
	}



	@Override
	public int getTotalByteLength() {
		if (signatureOfMessagesHash != null)
			return signatureOfMessagesHash.length + 4;
		else
			return 4;
	}

	public byte[] getSignatureOfMessagesHash() {
		return signatureOfMessagesHash;
	}

	public void setSignatureOfMessagesHash(byte[] signatureOfMessagesHash) {
		this.signatureOfMessagesHash = signatureOfMessagesHash;
		this.length = (short) signatureOfMessagesHash.length;
	}

	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		this.length = length;
	}

}
