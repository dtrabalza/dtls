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

/**
 * This class represents a certificate in the certificate list
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class SingleCertificate {
	// 3 bytes certificate_lenght
	private int certificate_lenght;

	// 0...2^24-1 bytes certificate
	private byte[] certificate;

	public int getCertificate_lenght() {
		return certificate_lenght;
	}

	public void setCertificate_lenght(int certificate_lenght) {
		this.certificate_lenght = certificate_lenght;
	}

	public byte[] getCertificate() {
		return certificate;
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}

	/**
	 * This method returns the total amount of bytes
	 * occupied by this certificate.
	 * It is the equivalent of the value of 
	 * certificate_lenght + 3
	 * @return
	 */
	public int getTotalByteLength() {
		return 3 + certificate.length;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(certificate);
		result = prime * result + certificate_lenght;
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
		SingleCertificate other = (SingleCertificate) obj;
		if (!Arrays.equals(certificate, other.certificate))
			return false;
		if (certificate_lenght != other.certificate_lenght)
			return false;
		return true;
	}

}
