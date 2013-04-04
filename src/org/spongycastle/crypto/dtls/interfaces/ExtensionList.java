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

public interface ExtensionList {
	
	/**
	 * Returns the raw bytes representing the data.
	 * The first value is the length (might be 1 or 2 bytes)
	 * followed by the serialized value of the elements
	 * @return
	 */
	public byte[] getBytes();
	
	/**
	 * Returns the length of the list
	 * included the length field
	 * It is obtained multiplying the number of
	 * elements of the list times the number
	 * of bytes required by each elements
	 * plus the length field
	 * @return
	 */
	public int getTotalByteValue();

	public void add(int data);
}
