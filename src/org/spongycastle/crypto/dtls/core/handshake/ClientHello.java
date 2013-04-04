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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.spongycastle.crypto.dtls.constants.Constants;
import org.spongycastle.crypto.dtls.core.Version;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;

/**
 * This class represents the client_hello message
 * sent by the client to initiate a new handshake
 * with the server.
 * RFC 6347 4.2.1
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class ClientHello implements HandshakeMessage {

	// 2 byte client version
	private Version client_version;
	// 32 bytes
	private byte[] random;
	// 1 byte
	private short session_id_length;
	// 0..32 bytes
	private byte[] session_id;
	// 1 byte
	private short cookie_length;
	// 0..32 bytes (2^8-1)
	private byte[] cookie;
	// 2 bytes
	private int cipher_suites_length;
	// 2..2^16-2 bytes
	// TODO: check
	private int[] cipher_suites;
	// 1 byte
	private short compression_methods_length;
	// 1..2^8-1 bytes
	private short[] compression_methods;
	
	//2 byte extensions length
	private int extensions_length;
	
	//Extensions
	private List<Extension> extensions;

	public ClientHello() {
		extensions = new ArrayList<Extension>();
	}

	public Version getClient_version() {
		return client_version;
	}

	public void setClient_version(Version client_version) {
		this.client_version = client_version;
	}

	public byte[] getRandom() {
		return random;
	}

	public void setRandom(byte[] random) {
		this.random = random;
	}

	public short getSession_id_length() {
		return session_id_length;
	}

	public void setSession_id_length(short session_id_length) {
		this.session_id_length = session_id_length;
	}

	public byte[] getSession_id() {
		return session_id;
	}

	public void setSession_id(byte[] session_id) {
		this.session_id = session_id;
	}

	public short getCookie_length() {
		return cookie_length;
	}

	public void setCookie_length(short cookie_length) {
		this.cookie_length = cookie_length;
	}

	public byte[] getCookie() {
		return cookie;
	}

	public void setCookie(byte[] cookie) {
		this.cookie = cookie;
	}

	public int getCipher_suites_length() {
		return cipher_suites_length;
	}

	public void setCipher_suites_length(int cipher_suites_length) {
		this.cipher_suites_length = cipher_suites_length;
	}

	public int[] getCipher_suites() {
		return cipher_suites;
	}

	public void setCipher_suites(int[] cipher_suites) {
		this.cipher_suites = cipher_suites;
	}

	public short getCompression_methods_length() {
		return compression_methods_length;
	}

	public void setCompression_methods_length(short compression_methods_length) {
		this.compression_methods_length = compression_methods_length;
	}

	public short[] getCompression_methods() {
		return compression_methods;
	}

	public void setCompression_methods(short[] compression_methods) {
		this.compression_methods = compression_methods;
	}
	
	public List<Extension> getExtensions() {
		return extensions;
	}

	public void setExtensions(List<Extension> extensions) {
		this.extensions = extensions;
	}
	
	public int getExtensions_length() {
		return extensions_length;
	}

	public void setExtensions_length(int extensions_length) {
		this.extensions_length = extensions_length;
	}

	/**
	 * Returns the bytes length of the message 
	 * @return
	 */
	public int getTotalByteLength(){
		int l = 39;	//static fields
		l += session_id_length;
		l += cookie_length;
		l += cipher_suites_length;
		l += compression_methods_length;
		if (extensions != null && (!extensions.isEmpty())){
			l += 2;	//2 bytes of extensions length
			for (Extension ext : extensions) {
				//get the length for each extension
				l += ext.getTotalByteLength(); 
			}
		}
		return l;
	}

	/**
	 * This method creates and return a client_hello message
	 * @param context client context
	 * @param cookie2 
	 * @return the client_hello message
	 */
	public static HandshakeMessage newClientHello(DTLSContext context, byte[] cookie) {
		ClientHello clientHello = new ClientHello();
		clientHello.setClient_version(new Version(Constants.CLIENT_VERSION_MAJOR, Constants.CLIENT_VERSION_MINOR));
		
		//if this is the first ClientHello generate the random number
		if (context.getSecurityParameters().getClientRandom() == null){
			
//			//initialize 32 bit random
//			byte[] rand = new byte[28];
//			
//			//generating the random
//			context.getRandomGenerator().nextBytes(rand);
//			
//			//obtaining the date
//			byte[] date = new String(new Long(System.currentTimeMillis()).toString()).getBytes();
			
			clientHello.setRandom(DTLSUtils.getNewRandom(context.getRandomGenerator()));
			
			//storing the local random in the context
			context.getSecurityParameters().setClientRandom(clientHello.getRandom());
		}else {
			clientHello.setRandom(context.getSecurityParameters().getClientRandom());
		}		
		//session_id empty

		//cookie
		if (cookie != null && cookie.length > 0){
			clientHello.setCookie(cookie);
			clientHello.setCookie_length((short)cookie.length);
		}

		//cipher suites
		clientHello.setCipher_suites(context.getLocalCipherSuites());
		
		//cipher suites length in bytes
		//2 bytes each so total_length = array_length * 2
		clientHello.setCipher_suites_length(clientHello.getCipher_suites().length * 2);
		
		//compression methods
		clientHello.setCompression_methods(context.getLocalCompressionMethods());

		//compression methods length
		//1 byte each
		clientHello.setCompression_methods_length((short)clientHello.getCompression_methods().length);
		
		//get extensions
		List<Extension> ext = context.selectExtensions(true);
		
		if (ext == null || ext.isEmpty()){
			clientHello.setExtensions_length(0);
		}else{
			clientHello.extensions.addAll(ext);
		
			//set extensions length
			int ext_length = 0;
			for (Extension ex : clientHello.getExtensions()) {
				ext_length += ex.getTotalByteLength();
			}
			clientHello.setExtensions_length(ext_length);
		}
				
		return clientHello;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(cipher_suites);
		result = prime * result + cipher_suites_length;
		result = prime * result
				+ ((client_version == null) ? 0 : client_version.hashCode());
		result = prime * result + Arrays.hashCode(compression_methods);
		result = prime * result + compression_methods_length;
		result = prime * result + Arrays.hashCode(cookie);
		result = prime * result + cookie_length;
		result = prime * result + Arrays.hashCode(random);
		result = prime * result + Arrays.hashCode(session_id);
		result = prime * result + session_id_length;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ClientHello other = (ClientHello) obj;
		if (!Arrays.equals(cipher_suites, other.cipher_suites))
			return false;
		if (cipher_suites_length != other.cipher_suites_length)
			return false;
		if (client_version == null) {
			if (other.client_version != null)
				return false;
		} else if (!client_version.equals(other.client_version))
			return false;
		if (!Arrays.equals(compression_methods, other.compression_methods))
			return false;
		if (compression_methods_length != other.compression_methods_length)
			return false;
		if (!Arrays.equals(cookie, other.cookie))
			return false;
		if (cookie_length != other.cookie_length)
			return false;
		if (!Arrays.equals(random, other.random))
			return false;
		if (!Arrays.equals(session_id, other.session_id))
			return false;
		if (session_id_length != other.session_id_length)
			return false;
		return true;
	}

//	@Override
//	public String toString() {
//		String result = "";
//		result += client_version.toString() + "";
//		result += DTLSUtils.printBytes(random) + "";
//		result += DTLSUtils.byteToBits(new Short(session_id_length).byteValue()) + "";
//		if (session_id_length != 0)
//			result += DTLSUtils.printBytes(session_id) + "";
//		result += DTLSUtils.byteToBits(new Short(cookie_length).byteValue()) + "";
//		if (cookie_length != 0)
//			result += DTLSUtils.printBytes(cookie) + "";
//		result += DTLSUtils.printBytes((DTLSUtils.getBytesFromValue(cipher_suites_length, 2))) + "";
//		if (cipher_suites_length != 0)
//			for (int i=0; i<cipher_suites.length;i++)
//				result += DTLSUtils.printBytes((DTLSUtils.getBytesFromValue(cipher_suites[i], 2))) + "";
//		result += DTLSUtils.byteToBits(new Short(compression_methods_length).byteValue()) + "";
//		if (compression_methods_length != 0)
//			for (int i=0; i<compression_methods_length;i++)
//				result += DTLSUtils.byteToBits(new Short(compression_methods[i]).byteValue()) + "";
//		return result;
//	}
	
	@Override
	public String toString() {
		String result = "";
		result += "ClientHello";
		return result;
	}

}
