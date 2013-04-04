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

import java.util.Arrays;

import org.spongycastle.crypto.dtls.constants.Constants;
import org.spongycastle.crypto.dtls.core.Version;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;

/**
 * This class represents the hello_verify_request message sent from the server
 * in response to the first client_hello message RFC 6347 4.2.1
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class HelloVerifyRequest implements HandshakeMessage {

	// 2 bytes client version
	private Version server_version;
	// 1 byte
	private short cookie_length;
	// 0..32 bytes (2^8-1)
	private byte[] cookie;

	public Version getServer_version() {
		return server_version;
	}

	public void setServer_version(Version server_version) {
		this.server_version = server_version;
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

	/**
	 * The total amount of bytes occupied by this field
	 * Same value as the value of cookie_length + 3
	 */
	public int getTotalByteLength() {
		if (cookie != null)
			return 3 + cookie.length;
		else
			return 3;
	}

	/**
	 * Creates and returns a new HelloVerifyRequest
	 * @param cookie2 
	 * @return
	 */
	public static HandshakeMessage newHelloVerifyRequest(byte[] newCookie) {
		HelloVerifyRequest helloVerifyRequest = new HelloVerifyRequest();
		
		helloVerifyRequest.setServer_version(new Version(
				Constants.SERVER_BASE_VERSION_MAJOR, 
				Constants.SERVER_BASE_VERSION_MINOR));
		//generate the cookie and put it in the context
		//to be verified when received the second ClientHello
		
		helloVerifyRequest.setCookie(newCookie);
		
		helloVerifyRequest.setCookie_length((short)newCookie.length);
		
		return helloVerifyRequest;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(cookie);
		result = prime * result + cookie_length;
		result = prime * result
				+ ((server_version == null) ? 0 : server_version.hashCode());
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
		HelloVerifyRequest other = (HelloVerifyRequest) obj;
		if (!Arrays.equals(cookie, other.cookie))
			return false;
		if (cookie_length != other.cookie_length)
			return false;
		if (server_version == null) {
			if (other.server_version != null)
				return false;
		} else if (!server_version.equals(other.server_version))
			return false;
		return true;
	}
	
	@Override
	public String toString() {
		String result = "";
		result += "HelloVerifyRequest";
		return result;
	}
	

}
