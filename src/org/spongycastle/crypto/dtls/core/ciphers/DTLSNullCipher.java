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

import org.spongycastle.crypto.dtls.core.RecordLayer;
import org.spongycastle.crypto.dtls.interfaces.DTLSAEADCipher;

/**
 * Null encryption. The plaintext and the ciphertext are the same.
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class DTLSNullCipher implements DTLSAEADCipher {

	public void encryptPlainText(RecordLayer plainText) {
		//populating the encrypted and compressed field 
		//with the result of the encryption (nothing to do here)
		plainText.setEncryptedAndCompressedFragment(plainText.getCompressedFragment());
	}

	public void decryptCipherText(RecordLayer ciphertext) {
		//populating the compressed field with the
		//encrypted and compressed record, result of the decryption (null here)
		ciphertext.setCompressedFragment(ciphertext.getEncryptedAndCompressedFragment());
	}

}
