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

import org.spongycastle.crypto.dtls.interfaces.FragmentType;

/**
 * This class represents the change_cipher_spec message.
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class ChangeCipherSpec implements FragmentType {

	private short change_cipher_spec;

	public short getChange_cipher_spec() {
		return change_cipher_spec;
	}

	public void setChange_cipher_spec(short change_cipher_spec) {
		this.change_cipher_spec = change_cipher_spec;
	}

	/**
	 * Space occupied in bytes of this object
	 */
	public int getTotalByteLength() {
		return 1;	//static field
	}

	/**
	 * A new ChangeCipherSpec message
	 * @return
	 */
	public static FragmentType getNewChangeCipherSpec() {

		ChangeCipherSpec changeCipherSpec = new ChangeCipherSpec();

		changeCipherSpec.setChange_cipher_spec(org.spongycastle.crypto.dtls.constants.ChangeCipherSpec.change_cipher_spec);

		return changeCipherSpec;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + change_cipher_spec;
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
		ChangeCipherSpec other = (ChangeCipherSpec) obj;
		if (change_cipher_spec != other.change_cipher_spec)
			return false;
		return true;
	}

	@Override
	public String toString() {
		String result = "";
		result += "ChangeCipherSpec";
		return result;
	}
}
