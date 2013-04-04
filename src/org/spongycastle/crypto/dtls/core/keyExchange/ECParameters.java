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
public class ECParameters {
	
	//ECCurveType    curve_type;
	//1 byte
	private short curve_type;
	
	//curve_type = named_curve(3)
//	case named_curve:
//		NamedCurve namedcurve;
	//2 bytes
	private int namedCurve;
	
	public ECParameters(short curve_type, int namedCurve) {
		this.curve_type = curve_type;
		this.namedCurve = namedCurve;
	}

	public ECParameters() {
		
	}

	public short getCurve_type() {
		return curve_type;
	}

	public void setCurve_type(short curve_type) {
		this.curve_type = curve_type;
	}

	public int getNamedCurve() {
		return namedCurve;
	}

	public void setNamedCurve(int namedCurve) {
		this.namedCurve = namedCurve;
	}

	public int getTotalByteLength() {
		return 3;
	}
}
