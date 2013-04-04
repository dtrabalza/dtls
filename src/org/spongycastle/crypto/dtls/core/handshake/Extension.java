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

import org.spongycastle.crypto.dtls.interfaces.ExtensionList;
import org.spongycastle.crypto.tls.ExtensionType;

public class Extension {

	// 2 bytes extension type (0..65535)
	private int type;

	// 2 bytes length
	private int extensionLength;

	// variable data
	private ExtensionList data;

	public Extension() {
//		data = new ArrayList<Object>();
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
		
		switch (type) {
		case ExtensionType.elliptic_curves:
			data = new Elliptic_Curve();
			break;

		case ExtensionType.ec_point_formats:
			data = new ECPointFormatList();
			break;

		default:
			break;
		}		
	}
	
	public void addSupportedExtensionType(int data) {
		//if type null raise TypeNotSpecifiedException
		this.data.add(data);
		
		//update length
		extensionLength = this.data.getTotalByteValue();
	}
	
	public int getExtensionLength() {
		return extensionLength;
	}

	public void setExtensionLength(int extensionLength) {
		this.extensionLength = extensionLength;
	}

	public ExtensionList getData() {
		return data;
	}

	public void setData(ExtensionList data) {
		this.data = data;
	}

	public int getTotalByteLength() {
		int l = 0;
		l += 4;	//static fields
		l += data.getTotalByteValue();
		return l;
	}

}
