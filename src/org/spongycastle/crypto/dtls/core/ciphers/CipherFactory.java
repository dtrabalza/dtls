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
package org.spongycastle.crypto.dtls.core.ciphers;

import org.spongycastle.crypto.dtls.core.DTLSProtocolHandler;
import org.spongycastle.crypto.dtls.core.SecurityParameters;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CCMBlockCipher;

public class CipherFactory {
	
	private DTLSProtocolHandler handler;
	
	private SecurityParameters secParams;

	public CipherFactory(DTLSProtocolHandler handler) {
		this.handler = handler;
		secParams = handler.getContext().getSecurityParameters();
	}

	public void prepareNewCipher(int encryptionAlgorithm, boolean isClient) {
		switch (encryptionAlgorithm) {
		case EncryptionAlgorithm.NULL: 
			handler.setPendingWriteCipher(new DTLSNullCipher());			
			handler.setPendingReadCipher(new DTLSNullCipher());
		break;
		case EncryptionAlgorithm.AES_CCM_8: 
			//key length = 128 bits
			secParams.setEncKeyLength(16);
			//draft-mcgrew-tls-aes-ccm-04 section 3
			secParams.setClient_write_IV_length(4);	//32 bits
			secParams.setServer_write_IV_length(4);	//32 bits
			
			//Generating session keys, MANDATORY!
			secParams.generateSessionKeys();
			
			if (isClient){
				handler.setPendingWriteCipher(new DTLSAESCCMCipher(handler,
						new CCMBlockCipher(new AESEngine()),
						secParams.getClient_write_key(),
						64));			
				handler.setPendingReadCipher(new DTLSAESCCMCipher(handler,
						new CCMBlockCipher(new AESEngine()),
						secParams.getServer_write_key(),
						64));	
			}else{
				handler.setPendingWriteCipher(new DTLSAESCCMCipher(handler,
						new CCMBlockCipher(new AESEngine()),
						secParams.getServer_write_key(),
						64));			
				handler.setPendingReadCipher(new DTLSAESCCMCipher(handler,
						new CCMBlockCipher(new AESEngine()),
						secParams.getClient_write_key(),
						64));
				}
			break;

		default:
			break;
		}
	}

}
