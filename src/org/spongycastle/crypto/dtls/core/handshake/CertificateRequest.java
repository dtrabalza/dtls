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

import java.util.ArrayList;
import java.util.List;

import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;

public class CertificateRequest implements HandshakeMessage {

	// 1 byte
	private short clientCertificateTypes_length;
	// 1 byte each
	private short[] clientCertificateTypes;

	// 2 bytes
	private int signatureAndHashAlgorithms_length;
	// from 2 to 16 bytes
	private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

	// 2 bytes
	private int distinguishedNames_length;
	// from 0 to 16 bytes
	private List<DistinguishedName> distinguishedNames;
	
	public CertificateRequest() {
		this.signatureAndHashAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		this.distinguishedNames = new ArrayList<DistinguishedName>();
	}

	public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms() {
		return signatureAndHashAlgorithms;
	}

	public short getClientCertificateTypes_length() {
		return clientCertificateTypes_length;
	}

	public void setClientCertificateTypes_length(short clientCertificateTypes_length) {
		this.clientCertificateTypes_length = clientCertificateTypes_length;
	}

	public short[] getClientCertificateTypes() {
		return clientCertificateTypes;
	}

	public void setClientCertificateTypes(short[] clientCertificateTypes) {
		this.clientCertificateTypes = clientCertificateTypes;
	}

	public int getSignatureAndHashAlgorithms_length() {
		return signatureAndHashAlgorithms_length;
	}

	public void setSignatureAndHashAlgorithms_length(
			int signatureAndHashAlgorithms_length) {
		this.signatureAndHashAlgorithms_length = signatureAndHashAlgorithms_length;
	}

	public int getDistinguishedNames_length() {
		return distinguishedNames_length;
	}

	public void setDistinguishedNames_length(int totLength) {
		this.distinguishedNames_length = totLength;
	}

	public void setSignatureAndHashAlgorithms(
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
		this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
	}

	public List<DistinguishedName> getDistinguishedNames() {
		return distinguishedNames;
	}

	public void setDistinguishedNames(List<DistinguishedName> distinguishedNames) {
		this.distinguishedNames = distinguishedNames;
	}

	@Override
	public int getTotalByteLength() {
		int tot = 5;	//static fields
//		if (clientCertificateTypes != null)
		tot += clientCertificateTypes_length;
//		if (signatureAndHashAlgorithms != null)
			//2 bytes each entry
		tot += signatureAndHashAlgorithms_length;
//		if (distinguishedNames != null)
		tot += getTotalDNLength(this);
		return tot;
	}

	/**
	 * Creates a Certificate Request message taking the parameters
	 * from the context, that in this case is the server context.
	 * @param context
	 * @return
	 */
	public static HandshakeMessage newCertificateRequest(DTLSContext context) {
		CertificateRequest certificateRequest = new CertificateRequest();
		
		//put the acceptable client authentication methods
		certificateRequest.setClientCertificateTypes(context.getClientCertificateTypes());
		
		//set the length
		if (certificateRequest.getClientCertificateTypes() != null)
			certificateRequest.setClientCertificateTypes_length((short)certificateRequest.getClientCertificateTypes().length);
		
		//put the supported signature and hash algorithms
		certificateRequest.setSignatureAndHashAlgorithms(context.getSupportedSignatureAndHashAlgorithms());
		
		//set the length (in bytes, 2 bytes each entry)
		if (certificateRequest.getSignatureAndHashAlgorithms() != null)
			certificateRequest.setSignatureAndHashAlgorithms_length((short)(certificateRequest.getSignatureAndHashAlgorithms().size()*2));
		
		//RFC 5246 section 7.4.4
		certificateRequest.setDistinguishedNames(context.getValidDN());
		
		//set the length of all the DN
		if ((certificateRequest.getDistinguishedNames() != null) && (!certificateRequest.getDistinguishedNames().isEmpty())){
			int totLength = getTotalDNLength(certificateRequest);
			certificateRequest.setDistinguishedNames_length(totLength);
		}
		
		return certificateRequest;
	}

	private static int getTotalDNLength(CertificateRequest certificateRequest) {
		int totLength = 0;
		for (DistinguishedName dn : certificateRequest.getDistinguishedNames()) {
			totLength += dn.getTotalByteLength();
		}
		return totLength;
	}

	@Override
	public String toString() {
		String result = "";
		result += "CertificateRequest";
		return result;
	}
}
