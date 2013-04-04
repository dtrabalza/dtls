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
package org.spongycastle.crypto.dtls.interfaces;

import org.spongycastle.crypto.dtls.core.RecordLayer;
import org.spongycastle.crypto.dtls.exceptions.DecryptionException;
import org.spongycastle.crypto.dtls.exceptions.EncryptionException;

public interface DTLSCipher{

	/**
	 * This method encrypts a DTLS Record.
	 * PRE: Before the encryption the record has been already
	 * compressed, and locate in a byte array variable.
	 * Since the encryption might need record parameters,
	 * the whole record is necessary for the encryption.
	 * POST: After this method is called, the field "compressed record"
	 * located in the RecordLayer object will be set to null, 
	 * and the field "compressed and encrypted record" will be
	 * populated with the result of the encryption of the compressed
	 * fragment (previously parsed from object in byte array)
	 * 
	 * @param plaintext
	 * @return
	 */
	public void encryptPlainText(RecordLayer plaintext) throws EncryptionException;

	/**
	 * This method decrypts a DTLS Record.
	 * PRE: in the record there is a field in which is presend the
	 * encrypted and compressed fragment.
	 * Since the decryption might need record parameters,
	 * the whole record is necessary for the decryption.
	 * After this method is called, the field "compressed record"
	 * located in the RecordLayer object will be populated with the 
	 * result of the decryption, and the field "compressed and encrypted record"
	 *  will be set to null
	 * 
	 * @param plaintext
	 * @return
	 */
	public void decryptCipherText(RecordLayer ciphertext) throws DecryptionException;

}
