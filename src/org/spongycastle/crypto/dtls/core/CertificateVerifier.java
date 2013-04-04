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
package org.spongycastle.crypto.dtls.core;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.spongycastle.crypto.dtls.core.context.DTLSECCContext;
import org.spongycastle.crypto.dtls.core.handshake.Certificate;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;

/**
 * This class verifies and validates a certificate.
 * A
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class CertificateVerifier {

	public static boolean isValidAndVerified(Certificate cert, DTLSContext context) {
		//certficate to validate
		X509Certificate certToAuthenticate = cert.getCertificates().get(0);
		
		//root certificate(s)
		Set<X509Certificate> roots = new HashSet<X509Certificate>();
		
		//intermediate certificates
		Set<X509Certificate> intermediates = new HashSet<X509Certificate>();
		
		//TODO: construct better the roots and intermediates
		for (java.security.cert.Certificate tmp : ((DTLSECCContext)context).getTrustAnchors()) {
			//put the root as such
			roots.add((X509Certificate) tmp);
			intermediates.add((X509Certificate) tmp);
		}
		
		boolean verified = false;
		try {
			verified = verifyCertificate(certToAuthenticate, roots,	intermediates);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		//TODO: check date and eventually CRLs
		
		return verified;
	}
	
	private static boolean verifyCertificate(X509Certificate cert, Set<X509Certificate> trustedRootCerts,
			Set<X509Certificate> intermediateCerts) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertPathBuilderException{
		
		// Create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector(); 
	    selector.setCertificate(cert);
	    
	    // Create the trust anchors (set of root CA certificates)
	    Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
	    for (X509Certificate trustedRootCert : trustedRootCerts) {
	    	trustAnchors.add(new TrustAnchor(trustedRootCert, null));
	    }
	    
	    // Configure the PKIX certificate builder algorithm parameters
	    PKIXBuilderParameters pkixParams = 
			new PKIXBuilderParameters(trustAnchors, selector);
		
		// Disable CRL checks (this is done manually as additional step)
		pkixParams.setRevocationEnabled(false);
	
		// Specify a list of intermediate certificates
		CertStore intermediateCertStore = CertStore.getInstance("Collection",
			new CollectionCertStoreParameters(intermediateCerts)/*, "BC"*/);
		pkixParams.addCertStore(intermediateCertStore);
	
		// Build and verify the certification chain
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX"/*, "BC"*/);
		PKIXCertPathBuilderResult result = 
			(PKIXCertPathBuilderResult) builder.build(pkixParams);
		
		return (result==null) ? false : true;
	}


}
