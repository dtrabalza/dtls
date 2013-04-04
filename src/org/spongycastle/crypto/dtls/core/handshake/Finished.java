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

import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;

/**
 * The finished message contains the hash of some of the
 * previous handshake messages.
 * For more information check RFC 5246 7.4.9
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class Finished implements HandshakeMessage {

	// variable length
	private byte[] finished;

	public byte[] getFinished() {
		return finished;
	}

	public void setFinished(byte[] finished) {
		this.finished = finished;
	}

	/**
	 * The total amount of bytes occupied by this field
	 */
	public int getTotalByteLength() {
		//TODO: it must have a value, temporary statement
		if (finished != null)
			return finished.length;
		else
			return 0;
	}

	/**
	 * 
	 * @param context
	 * @param verify_data 
	 * @return
	 */
	public static HandshakeMessage newFinished(DTLSContext context, byte[] verify_data) {
		Finished finished = new Finished();
		
		//verification data
		finished.setFinished(verify_data);
		
		return finished;
	}

	//TODO: WHY WITH THIS IS NOT WORKING?
	
//	@Override
//	public int hashCode() {
//		final int prime = 31;
//		int result = 1;
//		result = prime * result + Arrays.hashCode(finished);
//		return result;
//	}
//	
//	@Override
//	public boolean equals(Object obj) {
//		if (this == obj)
//			return true;
//		if (obj == null)
//			return false;
//		if (getClass() != obj.getClass())
//			return false;
//		Finished other = (Finished) obj;
//		if (!Arrays.equals(finished, other.finished))
//			return false;
//		return true;
//	}

	@Override
	public String toString() {
		String result = "";
		result += "Finished ";
		if (finished != null)
			result += DTLSUtils.getHexString(finished);
		return result;
	}
}
