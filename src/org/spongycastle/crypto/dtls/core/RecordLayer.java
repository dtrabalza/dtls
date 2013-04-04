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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.spongycastle.crypto.dtls.constants.Constants;
import org.spongycastle.crypto.dtls.constants.ContentType;
import org.spongycastle.crypto.dtls.core.ciphers.DTLSNullCipher;
import org.spongycastle.crypto.dtls.core.handshake.ChangeCipherSpec;
import org.spongycastle.crypto.dtls.exceptions.DecryptionException;
import org.spongycastle.crypto.dtls.exceptions.EncryptionException;
import org.spongycastle.crypto.dtls.exceptions.NoCMFoundException;
import org.spongycastle.crypto.dtls.exceptions.NoCSFoundException;
import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.FragmentType;
import org.spongycastle.crypto.dtls.interfaces.ServerKeyExchangeAlgorithm;

/**
 * This class represents the DTLS Record Layer (RFC 6347 4.1)
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class RecordLayer implements Comparable<RecordLayer>{
	
	/* STATIC FIELDS */
	//1 byte contentType
	private short contentType;
	//2 bytes protocolVersion
	private Version protocolVersion = null;
	//2 bytes epoch
	private int epoch;
	//6 bytes sequence_number
	private long sequence_number;
	//2 bytes length
	private int length; 
	
	/* FRAGMENT - Can be plaintext, compressed and compressed & encrypted */
	//plaintext: decrypted and decompressed payload of the record
	private FragmentType fragment = null;
	//compressed fragment
	private byte[] compressedFragment;
	//encrypted and compressed fragment
	private byte[] encryptedAndCompressedFragment;
	
	private Map<String, Object> additionalParametersMap;
	
	public RecordLayer() {
		additionalParametersMap = new HashMap<String, Object>();
	}

	public short getContentType() {
		return contentType;
	}

	public void setContentType(short contentType) {
		this.contentType = contentType;
	}

	public Version getProtocolVersion() {
		return protocolVersion;
	}

	public void setProtocolVersion(Version version) {
		this.protocolVersion = version;
	}

	public int getEpoch() {
		return epoch;
	}

	public void setEpoch(int epoch) {
		this.epoch = epoch;
	}

	public long getSequence_number() {
		return sequence_number;
	}

	public void setSequence_number(long sequence_number) {
		this.sequence_number = sequence_number;
	}

	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		this.length = length;
	}

	public FragmentType getFragment() {
		return fragment;
	}

	public void setFragment(FragmentType fragment) {
		this.fragment = fragment;
	}
	
	public byte[] getCompressedFragment() {
		return compressedFragment;
	}

	public void setCompressedFragment(byte[] compressedFragment) {
		this.compressedFragment = compressedFragment;
	}

	public Map<String, Object> getAdditionalParametersMap() {
		return additionalParametersMap;
	}
	
	public int getMessageSequence() throws ProgramErrorException{
		if (this.contentType == ContentType.handshake)
			return ((Fragment)fragment).getMessage_sequence();
		else
			throw new ProgramErrorException("Trying to obtain message sequence from a record that doesn't have one");
	}

	/**
	 * returns the total amount of bytes occupied from this record (included)
	 * and all the upper records in order to calculate the total dimension
	 * @return
	 */
	public int getTotalByteLength(){
		int length = 0;
		length += 13;	//fix fields
		if (encryptedAndCompressedFragment != null){
			if (fragment.getTotalByteLength() <= encryptedAndCompressedFragment.length)
				length += encryptedAndCompressedFragment.length;
		}else{
			length += fragment.getTotalByteLength();
		}
		return length;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + contentType;
		result = prime * result + epoch;
		result = prime * result
				+ ((fragment == null) ? 0 : fragment.hashCode());
//		result = prime * result + length;
		result = prime * result
				+ ((protocolVersion == null) ? 0 : protocolVersion.hashCode());
		return result;
	}

	/**
	 * Two record are the same if they have all the same fields
	 * except for the sequence_number that is increased every time
	 * and the fragment
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RecordLayer other = (RecordLayer) obj;
		if (contentType != other.contentType)
			return false;
		if (epoch != other.epoch)
			return false;
		if (fragment == null) {
			if (other.fragment != null)
				return false;
		} else if (!fragment.equals(other.fragment))
			return false;
//		if (length != other.length)
//			return false;
		if (protocolVersion == null) {
			if (other.protocolVersion != null)
				return false;
		} else if (!protocolVersion.equals(other.protocolVersion))
			return false;
		return true;
	}

//	@Override
//	public String toString() {
//		String result = "";
//		result += DTLSUtils.byteToBits(new Short(contentType).byteValue()) + "";
//		result += protocolVersion.toString() + "";
//		byte[] epochArray = ByteBuffer.allocate(4).putInt(epoch).array();
//		result += DTLSUtils.printBytes(Arrays.copyOfRange(epochArray, epochArray.length-2, epochArray.length) ) + "";
//		byte[] sequence_numberArray = ByteBuffer.allocate(8).putLong(sequence_number).array();
//		result += DTLSUtils.printBytes(Arrays.copyOfRange(sequence_numberArray, sequence_numberArray.length-6, sequence_numberArray.length) ) + "";
//		byte[] lengthArray = ByteBuffer.allocate(4).putInt(length).array();
//		result += DTLSUtils.printBytes(Arrays.copyOfRange(lengthArray, lengthArray.length-2, lengthArray.length) ) + "";
//		result += fragment.toString();
//		return result;
//	}
	
	@Override
	public String toString() {
		String result = "";
		result += " ContentType:" + contentType;
		if (fragment != null)
			result += fragment.toString();
		else
			result += "Encrypted Fragment";
		return result;
	}

	/**
	 * This method creates and return a full client hello message
	 * @param context 
	 * @param cookie 
	 * @return
	 */
	public static RecordLayer getNewClientHello(DTLSContext context, byte[] cookie) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.CLIENT_VERSION_MAJOR, Constants.CLIENT_VERSION_MINOR));

		//epoch and sequence number updated further on
		
		FragmentType fragment = Fragment.newClientHello(context, cookie);
		
		//message_sequence = 0 on the first clientHello		
		
		record.setFragment(fragment);
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}

	/**
	 * Creates and returns a new HelloVerifyRequest message
	 * @param context 
	 * @param clientAddress 
	 */
	public static RecordLayer getNewHelloVerifyRequest(byte[] cookie) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.getNewHelloVerifyRequest(cookie);
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}
	
	/**
	 * Creates and returns a new HelloVerifyRequest message
	 * @param context
	 * @return
	 * @throws NoCMFoundException 
	 * @throws NoCSFoundException 
	 */
	public static RecordLayer getNewServerHello(
			DTLSContext context) throws NoCSFoundException, NoCMFoundException {
		RecordLayer record = new RecordLayer();
		
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));
		
		//epoch and sequence number updated further on
		
		FragmentType fragment = Fragment.newServerHello(context);
		record.setFragment(fragment);
		//set length
		record.setLength(fragment.getTotalByteLength());

		
		return record;
	}

	/**
	 * Creates and returns a new Certificate message
	 * @param context
	 * @return
	 */
	public static RecordLayer getNewCertificate(DTLSContext context, boolean isClient) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newCertificate(context, isClient);
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}

	/**
	 * Creates and returns a new ServerHelloDone message
	 * @return
	 */
	public static RecordLayer getNewServerHelloDone() {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newServerHelloDone();
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}
	
	/**
	 * Creates and returns a new ServerHelloDone message
	 * @param exchange_keys 
	 * @return
	 */
	public static RecordLayer getNewClientKeyExchange(byte[] exchange_keys) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newClientKeyExchange(exchange_keys);
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}

	/**
	 * Creates and returns a ChangeCipherSpec message
	 * @return
	 */
	public static RecordLayer getNewChangeCipherSpec() {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.change_cipher_spec);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = ChangeCipherSpec.getNewChangeCipherSpec();
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;	
	}
	
	/**
	 * 
	 * @param context 
	 * @param verify_data 
	 * @return
	 */
	public static RecordLayer getNewFinished(DTLSContext context, byte[] verify_data) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newFinished(context, verify_data);
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}
	
	/**
	 * 
	 * @param context
	 * @return
	 */
	public static RecordLayer getNewCertificateRequest(DTLSContext context) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newCertificateRequest(context);
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}
	
	/**
	 * 
	 * A RecordLayer 'A' precedes RecordLayer 'B' if 
	 * 'A'.sequence_number < 'B'.sequence_number
	 * 
	 * It is also true the contrary RecordLayer 'A' > RecordLayer 'B'
	 * if 'A'.sequence_number > 'B'.sequence_number
	 */
	@Override
	public int compareTo(RecordLayer rec) {
		//the epoch is not taken in consideration since when
		//this comparison is made the records are al at the same
		//epoch
//		if (this.epoch != rec.getEpoch()){
//			//if the epoch is not the same, compare epoch
//			return new Integer(this.epoch).compareTo(rec.getEpoch());
//		}else{
			//if the same epoch, order by sequence number
			return new Long(sequence_number).compareTo(rec.getSequence_number());
//		}
	}

	/**
	 * Set the fragment for further decription and decompression
	 * @param encryptedAndCompressedFragment the fragment to be stored
	 */
	public void setEncryptedAndCompressedFragment(
			byte[] encryptedAndCompressedFragment) {
		
		this.encryptedAndCompressedFragment = encryptedAndCompressedFragment;
	}

	/**
	 * Decryption, decompression and parsing of the fragment
	 * 
	 * @param dtlsProtocolHandler
	 * @throws DecryptionException 
	 */
	public void decryptAndDecompressFragment(DTLSProtocolHandler handler) throws DecryptionException{
		if (encryptedAndCompressedFragment == null)
			//nothing to do
			return;
		
		if (!(this.contentType == ContentType.alert)){
			//decrypt
			handler.getReadCipher().decryptCipherText(this);
		}else{
			//Temporary for testing purpose
			new DTLSNullCipher().decryptCipherText(this);
		}		
		//decompress
		byte[] decompressedFragment = handler.getReadCompression().decompress(this.compressedFragment);
		
		//parse plaintext
		fragment = handler.getParser().parseRecordPayloadBytes(contentType,decompressedFragment);
	}
	
	/**
	 * Encrypts and compresses the fragment of the record with the current
	 * ciphersuite and compression method
	 * @throws IOException 
	 * @throws EncryptionException 
	 */
	 public void compressAndEncryptRecord(DTLSProtocolHandler handler) throws IOException, EncryptionException{
		//parse the payload in a byte array
		byte[] plaintext = handler.getParser().parseRecordPayload(contentType, fragment);
		
		//compression
		this.compressedFragment =  handler.getWriteCompression().compress(plaintext);
		
		if (!(this.contentType == ContentType.alert)){
			//encryption
			handler.getWriteCipher().encryptPlainText(this);
		}else{
			//Temporary for testing purpose
			new DTLSNullCipher().encryptPlainText(this);
		}
	}

	public byte[] getEncryptedAndCompressedFragment() {
		return encryptedAndCompressedFragment;
	}

	/**
	 * Creates a new Record Layer, and put in the payload
	 * the application data in plaintext.
	 * Epoch, sequence number are put successively
	 * The encryption is also done further on
	 * @param data
	 * @return
	 */
	public static RecordLayer getNewAppDataRecord(byte[] data) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.application_data);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));
		//epoch and sequence number updated further on
		FragmentType fragment = new ApplicationData(data); 
		record.setFragment(fragment);
		
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}

	/**
	 * This method is called after the encryption of the fragment.
	 * Since due to encryption the lenght might be different, it is
	 * necessary to calculate it and include it in the record fields
	 * for the recipient's decoding
	 */
	public void updateLength() {
		this.length = encryptedAndCompressedFragment.length;
	}
	
	public static RecordLayer getNewAlert(short alertLevel, short alertDescription, DTLSProtocolHandler handler) {
		
		RecordLayer alert = new RecordLayer();

		alert.setContentType(ContentType.alert);
		
		if (handler.isClient()){
			alert.setProtocolVersion(new Version(Constants.CLIENT_VERSION_MAJOR, Constants.CLIENT_VERSION_MINOR));
		}else{
			alert.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));
		}
		
		FragmentType fragment = new Alert(alertLevel, alertDescription);
		alert.setFragment(fragment);
		
		alert.setLength(fragment.getTotalByteLength());
		
		return alert;
	}

	public static RecordLayer getNewServerKeyExchange(DTLSContext context, ServerKeyExchangeAlgorithm keyExchange) {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newServerKeyExchange(context, keyExchange);
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}

	public static RecordLayer getNewCertificateVerify() {
		RecordLayer record = new RecordLayer();
		record.setContentType(ContentType.handshake);
		record.setProtocolVersion(new Version(Constants.SERVER_VERSION_MAJOR, Constants.SERVER_VERSION_MINOR));

		//epoch and sequence number updated further on

		FragmentType fragment = Fragment.newCertificateVerify();
		
		//message_sequence = 0 
		
		record.setFragment(fragment);
		
		//set length
		record.setLength(fragment.getTotalByteLength());
		
		return record;
	}
	
}
