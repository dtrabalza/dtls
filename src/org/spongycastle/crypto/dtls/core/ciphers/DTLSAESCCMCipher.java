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

//import org.spongycastle.crypto.CipherParameters;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Logger;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.dtls.core.DTLSProtocolHandler;
import org.spongycastle.crypto.dtls.core.RecordLayer;
import org.spongycastle.crypto.dtls.exceptions.DecryptionException;
import org.spongycastle.crypto.dtls.exceptions.EncryptionException;
import org.spongycastle.crypto.dtls.interfaces.DTLSAEADCipher;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;
import org.spongycastle.crypto.modes.CCMBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;

public class DTLSAESCCMCipher implements DTLSAEADCipher {
	
	private static final Logger LOG = Logger.getLogger(DTLSAESCCMCipher.class.getName());
	
	private CCMBlockCipher ccmBlockCipher;
	private byte[] key;
	private int macSize;
	private DTLSProtocolHandler handler;

	public DTLSAESCCMCipher(DTLSProtocolHandler handler, CCMBlockCipher cipher, byte[] key, int macSize) {
		this.handler = handler;
		this.ccmBlockCipher = cipher;
		this.key = key;
		this.macSize = macSize;
	}

	@Override
	public void encryptPlainText(RecordLayer record) throws EncryptionException{
		LOG.fine("Encrypting with CCM the record " + record);
		try {
			//generating associated data
			byte[] associatedData = getAssociatedData(record, true);
			LOG.finest("Associated data: " + DTLSUtils.getHexString(associatedData));

			//generating nonce
			byte[] nonce;
			if (handler.isClient())
				nonce = DTLSUtils.concat(
						handler.getContext().getSecurityParameters().getClient_write_IV(),
						getNonce(record));
			else
				nonce = DTLSUtils.concat(
						handler.getContext().getSecurityParameters().getServer_write_IV(),
						getNonce(record));
			
			LOG.finest("Nonce: " + DTLSUtils.getHexString(nonce));
			
			LOG.finest("Encryption Key: " + DTLSUtils.getHexString(key));
			
			LOG.finest("Fragment to encrypt: " + DTLSUtils.getHexString(record.getCompressedFragment()));
			
			byte[] explicit_IV = DTLSUtils.concat(
					DTLSUtils.getBytesFromValue(record.getEpoch(), 2), 
					DTLSUtils.getBytesFromValue(record.getSequence_number(), 6));

			LOG.finest("Explicit_IV: " + DTLSUtils.getHexString(explicit_IV));
			
			record.setEncryptedAndCompressedFragment(
					DTLSUtils.concat(explicit_IV,
					encrypt(ccmBlockCipher, key, nonce, associatedData, 
							record.getCompressedFragment(), macSize)));

//			System.out.print("Encrypted and compressed fragment (WITH IV)");
//			DTLSUtils.printArray(record.getEncryptedAndCompressedFragment());
			
			record.setCompressedFragment(null);
		} catch (IllegalStateException e) {
			throw new EncryptionException(e);
		} catch (InvalidCipherTextException e) {
			throw new EncryptionException(e);
		}
	}

	@Override
	public void decryptCipherText(RecordLayer record) throws DecryptionException{
		LOG.fine("Decrypting with CCM the record " + DTLSUtils.getDTLSRecordString(record));
		LOG.finest("record's seq_num: " + record.getSequence_number());
		try {
			//obtain the explicit IV
			byte[] explicit_IV = Arrays.copyOfRange(
					record.getEncryptedAndCompressedFragment(), 0, 8);

			LOG.finest("Explicit_IV: " + DTLSUtils.getHexString(explicit_IV));
			
			//Setting the fragment without explicit_IV
			record.setEncryptedAndCompressedFragment(
					Arrays.copyOfRange(record.getEncryptedAndCompressedFragment(), 8, 
							record.getEncryptedAndCompressedFragment().length));
			
			LOG.finest("Encrypted and compressed fragment" + DTLSUtils.getHexString(record.getEncryptedAndCompressedFragment()));

			//generating associated data
			byte[] associatedData = getAssociatedData(record, false);
			LOG.finest("Associated data" + DTLSUtils.getHexString(associatedData));
			
			//generating nonce
			byte[] nonce;
			if (handler.isClient())
				nonce = DTLSUtils.concat(
						handler.getContext().getSecurityParameters().getServer_write_IV(),
						getNonce(record));
			else
				nonce = DTLSUtils.concat(
						handler.getContext().getSecurityParameters().getClient_write_IV(),
						getNonce(record));
			
			LOG.finest("Nonce: " + DTLSUtils.getHexString(nonce));
			
			LOG.finest("Decryption Key: " + DTLSUtils.getHexString(key));
			
			record.setCompressedFragment(
					decrypt(ccmBlockCipher, key, nonce, associatedData, 
							record.getEncryptedAndCompressedFragment(), macSize));

			LOG.finest("Decrypted fragment (may be compressed): " + DTLSUtils.getHexString(record.getCompressedFragment()));

			record.setEncryptedAndCompressedFragment(null);
			
		} catch (IllegalStateException e) {
			System.out.println(e);
			System.out.println(e.getMessage());
			throw new DecryptionException(e);
		} catch (InvalidCipherTextException e) {
			System.out.println(e);
			System.out.println(e.getMessage());
			throw new DecryptionException(e);
		}
	}
	
	private byte[] encrypt(
	        CCMBlockCipher ccm,
	        byte[] key,
	        byte[] nonce,
	        byte[] assData,
	        byte[] plaintext,
	        int macSize
	        ) throws IllegalStateException, InvalidCipherTextException{
		ccm.init(true, new AEADParameters(new KeyParameter(key), macSize, nonce, assData));
		
		byte[] enc = new byte[plaintext.length + 8];
		
		int len = ccm.processBytes(plaintext, 0, plaintext.length, enc, 0);
		
		len += ccm.doFinal(enc, len);
		
		LOG.finest("MAC: " + DTLSUtils.getHexString(ccm.getMac()));
		
		LOG.finest("Encrypted fragment: " + DTLSUtils.getHexString(enc));
		
		return enc;
	}

	private byte[] decrypt(
	        CCMBlockCipher ccm,
	        byte[] key,
	        byte[] nonce,
	        byte[] assData,
	        byte[] ciphertext,
	        int macSize
	        ) throws IllegalStateException, InvalidCipherTextException{
		ccm.init(false, new AEADParameters(new KeyParameter(key), macSize, nonce, assData));
				
		byte[] plain = new byte[ciphertext.length + 8];
		
		int len = ccm.processBytes(ciphertext, 0, ciphertext.length, plain, 0);
		
		len += ccm.doFinal(plain, len);

		LOG.finest("MAC: " + DTLSUtils.getHexString(ccm.getMac()));
		
		LOG.finest("Plaintext fragment: " + DTLSUtils.getHexString(plain));
		
		return plain;
	}
	
	/**
	 * This method returns the associated data needed for authenticated encryption and 
	 * decryption
	 * RFC 5246 6.2.3.3.
	 * @param record
	 * @return
	 */
	private byte[] getAssociatedData(RecordLayer record, boolean forEncryption){
		/*
		 * additional_data = seq_num + TLSCompressed.type +
                    TLSCompressed.version + TLSCompressed.length;
		 */
		//6 bytes seq_num + 1 byte contentType + 2 bytes version + 2 bytes compressed length
		ByteBuffer associatedData = ByteBuffer.allocate(13);

		//2 bytes epoch
		associatedData.put(DTLSUtils.getBytesFromValue(record.getEpoch(), 2));
		
		//6 bytes seq_num
		associatedData.put(DTLSUtils.getBytesFromValue(record.getSequence_number(), 6));
		
		//1 byte contentType
		associatedData.put(new Short(record.getContentType()).byteValue());
		
		//2 bytes version
		associatedData.put((byte) ~new Short(record.getProtocolVersion().getMajor()).byteValue());
		associatedData.put((byte) ~new Short(record.getProtocolVersion().getMinor()).byteValue());
		
		if (forEncryption){
			//2 bytes compressed length
			associatedData.put(DTLSUtils.getBytesFromValue(record.getCompressedFragment().length, 2));
		}else{
			//2 bytes compressed length
			//subtracting the MAC LENGTH and the EXPLICIT IV to match the compressed length
			associatedData.put(DTLSUtils.getBytesFromValue(record.getEncryptedAndCompressedFragment().length-8, 2));
		}
		
		return associatedData.array();
	}
	
	/**
	 * This method returns a nonce according to
	 * draft-mcgrew-tls-aes-ccm-04 section 3
	 * 
	 *   struct {
	 *   	case client:
	 *      	uint32 client_write_IV;  // low order 32-bits
	 *      case server:
	 *          uint32 server_write_IV;  // low order 32-bits   
	 *      uint64 seq_num;    
	 *   } CCMNonce.     
	 *   
	 * In DTLS, the 64-bit seq_num is the 16-bit epoch concatenated 
	 * with the 48-bit seq_num.  
	 *            
	 * @param rec
	 * @return
	 */
	public byte[] getNonce(RecordLayer rec){
//		byte[] tmp = 
		return 
		DTLSUtils.concat(
				DTLSUtils.getBytesFromValue(rec.getEpoch(), 2), 
				DTLSUtils.getBytesFromValue(rec.getSequence_number(), 6));
//		System.out.println("LongNonce (" + tmp.length + ") :" + 		
//		DTLSUtils.printBytes(tmp));
		
		//taking low order 32 bits
//		byte[] sNonce = Arrays.copyOfRange(tmp, 4, tmp.length);
//		System.out.println("ShortNonce (" + sNonce.length + ") :" +		
//		DTLSUtils.printBytes(sNonce));

//		return sNonce;
	}

	public void extractParametersBeforeDecrypt(RecordLayer record) {
		//take the explicit IV from the encrypted and compressed fragment
		
		
	}
}
