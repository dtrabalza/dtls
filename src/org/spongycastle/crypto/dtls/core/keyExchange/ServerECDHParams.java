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
package org.spongycastle.crypto.dtls.core.keyExchange;

/**
 * RFC 4492 5.4
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class ServerECDHParams {

	private ECParameters curve_params;

	//1  byte length
	private int ecPointLength;
	
	//opaque point
	private byte[] ecPoint;

	public ServerECDHParams(ECParameters parameters) {
		this.curve_params = parameters;
	}

	public byte[] getEcPoint() {
		return ecPoint;
	}

	//setting length
	public void setEcPoint(byte[] ecPoint) {
		this.ecPoint = ecPoint;
		this.ecPointLength = ecPoint.length;
	}

	public ECParameters getCurve_params() {
		return curve_params;
	}

	public void setCurve_params(ECParameters curve_params) {
		this.curve_params = curve_params;
	}

	public void setEcPointLength(int ecPointLength) {
		this.ecPointLength = ecPointLength;
	}

	public int getEcPointLength() {
		return ecPointLength;
	}

	public int getTotalByteLength() {
		int result = 0;
		result += curve_params.getTotalByteLength();
		result += 1;
		result += ecPointLength;
		return result;
	}

}
