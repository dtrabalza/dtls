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

import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;

/**
 * This class represents the client_key_exchange message sent from the client to
 * the server during the handshake
 * 
 * RFC 5246 7.4.7
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class ClientKeyExchange implements HandshakeMessage {

	// 1 bytes length
	private int length;

	// variable length depending on the key exchange algorithm
	private byte[] exchange_keys;

	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		this.length = length;
	}

	public byte[] getExchange_keys() {
		return exchange_keys;
	}

	public void setExchange_keys(byte[] exchange_keys) {
		this.exchange_keys = exchange_keys;
	}

	/**
	 * The total amount of bytes occupied by this field
	 */
	public int getTotalByteLength() {	
		if (exchange_keys != null)
			return exchange_keys.length + 1;
		else
			return 0;
	}

	/**
	 * Creates and return a new ClientKeyExchange
	 * handshake message
	 * @param exchange_keys2
	 * @return
	 */
	public static HandshakeMessage newClientKeyExchange(byte[] exchange_keys) {
		ClientKeyExchange clientKeyExchange = new ClientKeyExchange();
		
		clientKeyExchange.setExchange_keys(exchange_keys);
		if (exchange_keys != null && exchange_keys.length > 0)
			clientKeyExchange.setLength(exchange_keys.length);
		else
			clientKeyExchange.setLength(0);
		
		return clientKeyExchange;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(exchange_keys);
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
		ClientKeyExchange other = (ClientKeyExchange) obj;
		if (!Arrays.equals(exchange_keys, other.exchange_keys))
			return false;
		return true;
	}
	
	@Override
	public String toString() {
		String result = "";
		result += "ClientKeyExchange";
		return result;
	}

}
