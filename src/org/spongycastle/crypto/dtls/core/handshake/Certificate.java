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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.spongycastle.crypto.dtls.core.context.DTLSECCContext;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;

/**
 * This class represents the certificate message optionally sent by the client
 * and the server to exchange the certificate RFC 6347 4.2.1
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class Certificate implements HandshakeMessage {

	// 3 bytes certificates_length
	private int certificates_length;

	private List<X509Certificate> certificates;
	
	public Certificate() {
		certificates =  new ArrayList<X509Certificate>();
	}

	public int getCertificates_length() {
		return certificates_length;
	}

	public void setCertificates_length(int certificates_length) {
		this.certificates_length = certificates_length;
	}

	/**
	 * returns the total amount of bytes occupied by
	 * all the certificates plus the field containing
	 * their length.
	 * It is the same as the value of certificates_length + 3
	 */
	public int getTotalByteLength() {
		int length = 0;
		length += 3;	//static field
		if (certificates != null)
			for (X509Certificate singleCertificate : certificates)
				try {
					//including the 3 bytes length for each certificate
					length += (singleCertificate.getEncoded().length + 3);
				} catch (CertificateEncodingException e) {
					e.printStackTrace();
					return 0;
				}
		return length;
	}

	public List<X509Certificate> getCertificates() {
		return certificates;
	}

	public void setCertificates(List<X509Certificate> certificates) {
		this.certificates = certificates;
	}

	/**
	 * Creates and return a new Certificate message based on
	 * the parameters contained in the context
	 * @param context
	 * @return
	 */
	public static HandshakeMessage newCertificate(DTLSContext context, boolean isClient) {
		Certificate certificate = new Certificate();
		
		java.security.cert.Certificate[] chain = null;
		if (!isClient)
			chain = ((DTLSECCContext)context).getServerChain();
		else{
			java.security.cert.Certificate[] c = new java.security.cert.Certificate[1];
			c[0] = ((DTLSECCContext)context).getClientCertificate();
			chain = c;
		}
		
		int totalLength = 0;
		
		//iterate for the whole list of certificates
		for (int i = 0; i < chain.length; i++) {
			certificate.certificates.add((X509Certificate) chain[i]);

			try {
				totalLength += chain[i].getEncoded().length +3;
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		certificate.setCertificates_length(totalLength);

		return certificate;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((certificates == null) ? 0 : certificates.hashCode());
		result = prime * result + certificates_length;
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
		Certificate other = (Certificate) obj;
		if (certificates == null) {
			if (other.certificates != null)
				return false;
		} else if (!certificates.equals(other.certificates))
			return false;
		if (certificates_length != other.certificates_length)
			return false;
		return true;
	}
	
	@Override
	public String toString() {
		String result = "";
		result += "Certificate";
		return result;
	}
	
}