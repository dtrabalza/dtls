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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.spongycastle.crypto.dtls.interfaces.ExtensionList;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;

public class Elliptic_Curve implements ExtensionList {
	
	private final static int BYTES_SINGLE_ELEMENT = 2;
	
	private final static int BYTES_LENGTH = 2;

	private List<Integer> named_curve;
	
	public Elliptic_Curve() {
		this.named_curve = new ArrayList<Integer>();
	}
	
	@Override
	public void add(int data) {
		named_curve.add(new Integer(data));
	}
	
	private int getListLength(){
//		System.out.println("list length = " + named_curve.size() * BYTES_SINGLE_ELEMENT);
		return named_curve.size() * BYTES_SINGLE_ELEMENT;
	}

	@Override
	public int getTotalByteValue() {
		return BYTES_LENGTH + getListLength();
	}

	@Override
	public byte[] getBytes() {
		byte[] bytes = 
				DTLSUtils.concat(
						DTLSUtils.getBytesFromValue(getListLength(), BYTES_LENGTH),
						getListBytesValue());
		return bytes;
	}

	private byte[] getListBytesValue() {
		ByteBuffer list = ByteBuffer.allocate(getListLength());
		
		for (Integer i : named_curve)
			list.put(DTLSUtils.getBytesFromValue(i.intValue(), 2));
		
		return list.array();
	}

}
