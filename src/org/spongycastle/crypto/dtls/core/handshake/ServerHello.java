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
import org.spongycastle.crypto.dtls.exceptions.NoCMFoundException;
import org.spongycastle.crypto.dtls.exceptions.NoCSFoundException;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;

public class ServerHello implements HandshakeMessage {

	// 2 byte client version
	private Version server_version;
	// 32 bytes
	private byte[] random;
	// 1 byte
	private short session_id_length;
	// 0..32 bytes
	private byte[] session_id;	//0 if it is not possible to resume the session
	// 2 bytes
	private int cipher_suite;
	// 1 byte
	private short compression_method;
	
	//2 byte extensions length
	private int extensions_length;
	
	//Extensions
	private List<Extension> extensions;
	
	public ServerHello() {
		extensions = new ArrayList<Extension>();
		//initialize 32 bit space for the random
		random = new byte[32];
	}

	public Version getServer_version() {
		return server_version;
	}

	public void setServer_version(Version server_version) {
		this.server_version = server_version;
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

	public int getCipher_suite() {
		return cipher_suite;
	}

	public void setCipher_suite(int cipher_suite) {
		this.cipher_suite = cipher_suite;
	}

	public short getCompression_method() {
		return compression_method;
	}

	public void setCompression_method(short compression_method) {
		this.compression_method = compression_method;
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
	 * Return the total amount of bytes occupied by this
	 * object
	 */
	public int getTotalByteLength() {
		int length = 0;
		length += 38;	//static fields
		if (session_id != null)
			length += session_id.length;	//it might be 0
		if (extensions != null && (!extensions.isEmpty())){
			length += 2;	//2 bytes of extensions length
			for (Extension ext : extensions) {
				//get the length for each extension
				length += ext.getTotalByteLength(); 
			}
		}
		
		return length;
	}

	/**
	 * Generates a new ServerHello message,
	 * Thanks to the context, it gets the offered cipher suites, and the
	 * compression methods, and selects them. If the selection is not 
	 * successful, a proper exception is raised.
	 * @param context
	 * @return
	 * @throws NoCSFoundException
	 * @throws NoCMFoundException 
	 */
	public static HandshakeMessage newServerHello(DTLSContext context) throws NoCSFoundException, NoCMFoundException {
		ServerHello serverHello = new ServerHello();
		serverHello.setServer_version(new Version(Constants.SERVER_BASE_VERSION_MAJOR, Constants.SERVER_BASE_VERSION_MINOR));
		
		//generating the random
		serverHello.setRandom(DTLSUtils.getNewRandom(context.getRandomGenerator()));
		//storing the local random in the context
		context.getSecurityParameters().setServerRandom(serverHello.getRandom());
		
		//TODO: implement session caching and consequently sessionID
		//now it is null (0)
		
		serverHello.setCipher_suite(context.selectCipherSuite());
		
		//store the selection in the context
		context.setSelectedCipherSuite(serverHello.getCipher_suite());
		
		serverHello.setCompression_method(context.selectCompressionMethod());
		
		//store the selection in the context
		context.setSelectedCompressionMethod(serverHello.getCompression_method());
		
		//select extensions
		List<Extension> ext = context.selectExtensions(false);
		
		if (ext == null || ext.isEmpty()){
			serverHello.setExtensions_length(0);
		}else{
			serverHello.extensions.addAll(ext);
		
			//set extensions length
			int ext_length = 0;
			for (Extension ex : serverHello.getExtensions()) {
				ext_length += ex.getTotalByteLength();
			}
			serverHello.setExtensions_length(ext_length);
		}

		return serverHello;
	}
	
//	@Override
//	public String toString() {
//		String result = "";
//		
//		result += server_version.toString() + "";
//		
//		result += DTLSUtils.printBytes(random) + "";
//		
//		result += DTLSUtils.byteToBits(new Short(session_id_length).byteValue()) + "";
//		
//		if (session_id_length != 0)
//			result += DTLSUtils.printBytes(session_id) + "";
//		
//		result += DTLSUtils.printBytes(DTLSUtils.getBytesFromValue(cipher_suite, 2));
//		
//		result += DTLSUtils.byteToBits(new Short(compression_method).byteValue());
//
//		return result;
//	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + cipher_suite;
		result = prime * result + compression_method;
		result = prime * result + Arrays.hashCode(random);
		result = prime * result
				+ ((server_version == null) ? 0 : server_version.hashCode());
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
		ServerHello other = (ServerHello) obj;
		if (cipher_suite != other.cipher_suite)
			return false;
		if (compression_method != other.compression_method)
			return false;
		if (!Arrays.equals(random, other.random))
			return false;
		if (server_version == null) {
			if (other.server_version != null)
				return false;
		} else if (!server_version.equals(other.server_version))
			return false;
		if (!Arrays.equals(session_id, other.session_id))
			return false;
		if (session_id_length != other.session_id_length)
			return false;
		return true;
	}

	@Override
	public String toString() {
		String result = "";
		result += "ServerHello";
		return result;
	}
	
}
