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

public class ECPointFormatList implements ExtensionList{
	
	private final static int BYTES_SINGLE_ELEMENT = 1;
	
	private final static int BYTES_LENGTH = 1;
	
	private List<Short> ec_point_format;

	public ECPointFormatList() {
		this.ec_point_format = new ArrayList<Short>();
	}
	
	private int getListLength(){
		return ec_point_format.size() * BYTES_SINGLE_ELEMENT;
	}

	@Override
	public int getTotalByteValue() {
		return BYTES_LENGTH + getListLength();
	}

	@Override
	public void add(int data) {
		ec_point_format.add(new Short((short) data));
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
		
		for (Short s : ec_point_format)
			list.put(s.byteValue());
		
		return list.array();
	}
}
