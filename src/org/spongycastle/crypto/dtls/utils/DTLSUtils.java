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
package org.spongycastle.crypto.dtls.utils;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.dtls.constants.ContentType;
import org.spongycastle.crypto.dtls.constants.HandshakeType;
import org.spongycastle.crypto.dtls.core.Fragment;
import org.spongycastle.crypto.dtls.core.RecordLayer;
import org.spongycastle.crypto.dtls.core.handshake.Certificate;
import org.spongycastle.crypto.dtls.core.handshake.CertificateRequest;
import org.spongycastle.crypto.dtls.core.handshake.ClientHello;
import org.spongycastle.crypto.dtls.core.handshake.Finished;
import org.spongycastle.crypto.dtls.core.handshake.HelloVerifyRequest;
import org.spongycastle.crypto.dtls.core.handshake.ServerHello;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

public class DTLSUtils {

	public static int getBit(byte[] data, int pos) {
		int posByte = pos / 8;
		int posBit = pos % 8;
		byte valByte = data[posByte];
		int valInt = valByte >> (8 - (posBit + 1)) & 0x0001;
		return valInt;
	}

	public static void setBit(byte[] data, int pos, int val) {
		int posByte = pos / 8;
		int posBit = pos % 8;
		byte oldByte = data[posByte];
		oldByte = (byte) (((0xFF7F >> posBit) & oldByte) & 0x00FF);
		byte newByte = (byte) ((val << (8 - (posBit + 1))) | oldByte);
		data[posByte] = newByte;
	}

//	public static void printBytes(byte[] data, String name) {
//		System.out.println("");
//		System.out.println(name + ":");
////		for (int i = 0; i < data.length; i++) {
////			System.out.print(byteToBits(data[i]) + " ");
////		}
////		System.out.println();
//	}

	public static String byteToBits(byte b) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < 8; i++)
			buf.append((int) (b >> (8 - (i + 1)) & 0x0001));
		return buf.toString();
	}
	
//	/**
//	 * Prints the bits of the given byte array
//	 * @param data
//	 * @return
//	 */
//	public static String printBytes(byte[] data) {
//		StringBuffer buf = new StringBuffer();
//		for (int i = 0; i < data.length; i++) 
//			buf.append(byteToBits(data[i]));
//		return buf.toString();
//	}
	
	/**
	 * This method retrieves a long from a byte array
	 * @param arr maximum 8 bytes
	 * @return the long value of the binary array where the first byte
	 * is the most significant
	 */
	public static long getValue(byte[] arr){
		long value = 0;
		for (int i = 0; i < arr.length; i++)
		   value = (value << 8) + (arr[i] & 0xff);
		return value;
	}
    
    /**
     * This method returns 2 bytes of the integer value
     * specified as parameter.
     * NOTE: if byteNum = 2 the integer value is truncated 
     * to 2 bytes value converted to int 
     * @param value the integer to convert in bytes
     * @return
     */
    public static byte[] getBytesFromValue(int value, int byteNum){
    	byte[] array = ByteBuffer.allocate(4).putInt(value).array();
    	return Arrays.copyOfRange(array, array.length-byteNum, array.length);
    }
    
    /**
     * Returns the rightmost byteNum bytes specified from the
     * value converted in byte array.
     * NOTE: if byteNum = 2 the integer value is truncated 
     * to 2 bytes value converted to long 
     * @param value the value to convert
     * @param byteNum the number of rightmost bytes to obtain
     * @return
     */
    public static byte[] getBytesFromValue(long value, int byteNum){
    	byte[] array = ByteBuffer.allocate(8).putLong(value).array();
    	return Arrays.copyOfRange(array, array.length-byteNum, array.length);
    }

    /**
     * prints a list of records
     * @param recList the list to print
     */
    public static String getDTLSRecordsString(List<RecordLayer> recList){

    	StringBuffer strBuf = new StringBuffer();
    	strBuf.append("\n--- START FLIGHT ---");
//    	strBuf.append("\n");
    	for (RecordLayer rec : recList){
    		strBuf.append(getDTLSRecordString(rec));
    	}
    	strBuf.append("--- END FLIGHT ---");
    	
    	return strBuf.toString();
	}
    
    /**
     * Prints in a human readable format a Record Layer
     * @param rec the record to print
     */
    public static String getDTLSRecordString(RecordLayer rec){
    	StringBuffer strBuf = new StringBuffer();
    	strBuf.append("\n[DTLS Record] ");
		strBuf.append("Content type: " + rec.getContentType());
		strBuf.append(" Version: " + rec.getProtocolVersion().getMajor() + "." + rec.getProtocolVersion().getMinor());
		strBuf.append(" Epoch: " + rec.getEpoch());
		strBuf.append(" Sequence Number: " + rec.getSequence_number());
		strBuf.append(" Length: " + rec.getLength());
		strBuf.append("\n");
		
		
		if ((rec.getContentType() == ContentType.handshake) &&
				(rec.getFragment() != null)){

			Fragment fragment = (Fragment) rec.getFragment();
			strBuf.append(" [Handshake Fragment] ");
			strBuf.append(" Message type: " + fragment.getMessage_type());
			strBuf.append(" Length: " + fragment.getLength());
			strBuf.append(" Message Sequence: " + fragment.getMessage_sequence());
			strBuf.append(" Fragment Offset: " + fragment.getFragment_offset());
			strBuf.append(" Fragment Length: " + fragment.getFragment_length());
			strBuf.append("\n");
			
			switch (fragment.getMessage_type()) {
				case HandshakeType.client_hello:
					
					ClientHello clientHello = (ClientHello)fragment.getBody();
					strBuf.append("  [ClientHello]");
					strBuf.append(" Client Version: " + clientHello.getClient_version().getMajor() + "." + clientHello.getClient_version().getMinor());
					strBuf.append(" Random: " + clientHello.getRandom());
					strBuf.append(" SessionID_length: " + clientHello.getSession_id_length());
					strBuf.append(" SessionID: " + clientHello.getSession_id());
					strBuf.append(" Cookie_length: " + clientHello.getCookie_length());
					strBuf.append(" Cookie: " + clientHello.getCookie());
					strBuf.append(" CipherSuites_length: " + clientHello.getCipher_suites_length());
					strBuf.append(" CipherSuites: " + clientHello.getCipher_suites());
					strBuf.append(" CompressionMethods_length: " + clientHello.getCompression_methods_length());
					strBuf.append(" CompressionMethods: " + clientHello.getCompression_methods());
					strBuf.append("\n");
					break;
					
				case HandshakeType.hello_verify_request:
					
					HelloVerifyRequest helloVerifyRequest = (HelloVerifyRequest)fragment.getBody();
					strBuf.append("  [HelloVerifyRequest]");
					strBuf.append(" Server Version: " + helloVerifyRequest.getServer_version().getMajor() + "." + helloVerifyRequest.getServer_version().getMinor());
					strBuf.append(" Cookie_length: " + helloVerifyRequest.getCookie_length());
					strBuf.append(" Cookie: " + helloVerifyRequest.getCookie());
					strBuf.append("\n");
					break;
					
				case HandshakeType.server_hello:
					
					ServerHello serverHello = (ServerHello)fragment.getBody();
					strBuf.append("  [ServerHello]");
					strBuf.append(" Server Version: " + serverHello.getServer_version().getMajor() + "." + serverHello.getServer_version().getMinor());
					strBuf.append(" Random: " + serverHello.getRandom());
					strBuf.append(" SessionID_length: " + serverHello.getSession_id_length());
					strBuf.append(" SessionID: " + serverHello.getSession_id());
					strBuf.append(" CipherSuite: " + serverHello.getCipher_suite());
					strBuf.append(" CompressionMethod: " + serverHello.getCompression_method());
					strBuf.append("\n");
					break;
					
				case HandshakeType.certificate:
					
					Certificate certificate = (Certificate)fragment.getBody();
					strBuf.append("  [Certificate]");
					
//					for (X509Certificate cert : certificate.getCertificates()) {
//						strBuf.append(cert);
//					}
//					strBuf.append("\n");
					break;
					
				case HandshakeType.server_key_exchange:

//					ServerKeyExchange serverKeyExchange = (ServerKeyExchange)fragment.getBody();
					strBuf.append("  [ServerKeyExchange]");
					strBuf.append("\n");
					break;
					
				case HandshakeType.certificate_request:
//					
					CertificateRequest certificateRequest = (CertificateRequest)fragment.getBody();
					strBuf.append("  [CertificateRequest]");
					strBuf.append("\n");
					break;	
					
				case HandshakeType.server_hello_done:
					
					strBuf.append("  [ServerHelloDone]");
					strBuf.append("\n");
					break;
					
				case HandshakeType.client_key_exchange:
					
//					ClientKeyExchange clientKeyExchange = (ClientKeyExchange)fragment.getBody();
					strBuf.append("  [ClientKeyExchange]");
					strBuf.append("\n");
					break;
					
				case HandshakeType.certificate_verify:
					
//					CertificateVerify certificateVerify = (CertificateVerify)fragment.getBody();
					strBuf.append("  [CertificateVerify]");
					strBuf.append("\n");
					break;
					
				case HandshakeType.finished:
					
					Finished finished = (Finished)fragment.getBody();
					strBuf.append("  [Finished] ");
					strBuf.append(getHexString(finished.getFinished()));
					strBuf.append("\n");
					break;
					
				default:
					break;
				
			}
		}else if (rec.getContentType() == ContentType.change_cipher_spec){
			strBuf.append(" [ChangeCipherSpec]\n");
    	}else if (rec.getContentType() == ContentType.application_data){
    		strBuf.append(" [Application Data]\n");
    	}else if (rec.getContentType() == ContentType.alert){
    		strBuf.append(" [Alert]\n");
    	}
    	
    	return strBuf.toString();
    }
    
    /**
     * From TlsUtils
     * @param a
     * @param b
     * @return
     */
    public static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
    
    /**
     * 
     * @param secret
     * @param label
     * @param seed
     * @param outputSize
     * @return
     */
	public static byte[] PRF(byte[] secret, byte[] label, byte[] seed, int outputSize){
		return P_hash(secret, DTLSUtils.concat(label, seed), new SHA256Digest(), outputSize);
	}
	
	public static byte[] P_hash(byte[] secret, byte[] seed, Digest digest, int outputSize){
        /*
         * compute:
         *
         *     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
         *                            HMAC_hash(secret, A(2) + seed) +
         *                            HMAC_hash(secret, A(3) + seed) + ...
         * A() is defined as:
         *
         *     A(0) = seed
         *     A(i) = HMAC_hash(secret, A(i-1))
         */
		
		if (secret == null)
			secret = new byte[]{};
		
		//initializing digest and the key
		HMac hmac = new HMac(digest);
		hmac.init(new KeyParameter(secret));
		
		//allocating more space than needed because the exceeding bytes are discarded
		ByteBuffer result = ByteBuffer.allocate(outputSize + digest.getDigestSize());

		//Temporary digest for A(i) = HMAC_hash(secret, A(i-1))
		byte[] tmpAi = new byte[digest.getDigestSize()];
		//HMAC_hash(secret, A(1) + seed)
		byte[] tmp = new byte[digest.getDigestSize()];
		//bytes to be hashed
		byte[] toHash;		
		
		while (result.position() < outputSize){
			if (result.position() == 0){
				//compute A(0)
				hmac.update(seed, 0, seed.length);
				hmac.doFinal(tmpAi, 0);
//				System.out.print("A(0):" );
//				printArray(tmpAi);				
			}else{
				//compute A(i)
				hmac.update(tmpAi,0,tmpAi.length);
				hmac.doFinal(tmpAi, 0);
//				System.out.print("A(i):" );
//				printArray(tmpAi);
			}
			toHash = DTLSUtils.concat(tmpAi, seed);
			hmac.update(toHash,0,toHash.length);
			hmac.doFinal(tmp, 0);
			
//			System.out.print("Putting in the result:" );
//			printArray(tmp);
			result.put(tmp);
		}
		
		return Arrays.copyOfRange(result.array(), 0, outputSize);
	}
	
	public static String getHexString(byte[] arr){
		return new String(Hex.encode(arr));
	}
    
//	@Deprecated
//    public static void printArray(byte[] arr){
//    	System.out.println("(ToBeDeleted)" + new String(Hex.encode(arr)));
//	}

	public static byte[] getNewRandom(SecureRandom secureRandom) {
		//initialize 32 bit random
		byte[] rand = new byte[32];
		
		//generating the random
		secureRandom.nextBytes(rand);
		
		//obtaining the date 4 bytes
		long tmp = System.currentTimeMillis() / 1000;
		int gmt_unix_time;

		if (tmp < Integer.MAX_VALUE) {
			gmt_unix_time = (int) tmp;
		}else{
			gmt_unix_time = Integer.MAX_VALUE;
		}
		
		//inserting current date
		rand[0] = (byte)(gmt_unix_time >> 24);
		rand[1] = (byte)(gmt_unix_time >> 16);
		rand[2] = (byte)(gmt_unix_time >>  8);
		rand[3] = (byte)gmt_unix_time;
	
		return rand;

	}

	public static String getCertificateChainString(
			List<X509Certificate> certificates) {
		StringBuffer strBuff = new StringBuffer();
		for (X509Certificate x509Certificate : certificates) {
			strBuff.append(x509Certificate.toString());
		}
		return strBuff.toString();
	}

}
