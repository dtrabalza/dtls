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

import java.security.Key;
import java.security.SecureRandom;
import java.util.List;

import org.spongycastle.crypto.dtls.core.DTLSProtocolHandler;
import org.spongycastle.crypto.dtls.core.RecordLayer;
import org.spongycastle.crypto.dtls.core.SecurityParameters;
import org.spongycastle.crypto.dtls.core.handshake.DistinguishedName;
import org.spongycastle.crypto.dtls.core.handshake.Extension;
import org.spongycastle.crypto.dtls.core.handshake.SignatureAndHashAlgorithm;
import org.spongycastle.crypto.dtls.exceptions.NoCMFoundException;
import org.spongycastle.crypto.dtls.exceptions.NoCSFoundException;
import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;
import org.spongycastle.crypto.dtls.exceptions.SignatureNotValidException;

public interface DTLSContext {

	public SecureRandom getRandomGenerator();
	
	public SecurityParameters getSecurityParameters();
	
	public int[] getLocalCipherSuites();
	
	public short[] getLocalCompressionMethods();
	
	public int[] getOfferedCipherSuites();
	
	public short[] getOfferedCompressionMethods();
	
	public void setOfferedCipherSuites(int[] offeredCipherSuites);
	
	public void setOfferedCompressionMethods(short[] offeredCompressionMethods);
	
	public void setSelectedCipherSuite(int selectedCipgerSuite);
	
	public void setSelectedCompressionMethod(int selectedCompressionMethod);

	public byte[] getPreMasterSecret();

	public void selectCipherAndCompression(DTLSProtocolHandler dtlsProtocolHandler);

	/**
	 * rfc5246
	 * This method returns the types of certificate the server
	 * requires to the client for the mutual authentication.
	 * Values are:
	 * enum {
          rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
          rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
          fortezza_dms_RESERVED(20), (255)
      } ClientCertificateType;
      
	 * @return
	 */
	public short[] getClientCertificateTypes();

	/**
	 * rfc5246
	 * Supported signature and hash algorithms
	 * struct {
             HashAlgorithm hash;
             SignatureAlgorithm signature;
       } SignatureAndHashAlgorithm;
       
      enum {
          none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
          sha512(6), (255)
      } HashAlgorithm;

      enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
        SignatureAlgorithm;
      
	 * @return
	 */
	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms();

	/**
	 * Returns the list of acceptable DN of CA
	 * opaque DistinguishedName<1..2^16-1>;
	 * @return
	 */
	public List<DistinguishedName> getValidDN();
	
	public RecordLayer getServerKeyExchange() throws ProgramErrorException;
	
	public RecordLayer getClientKeyExchange() throws ProgramErrorException;	
	
	public int selectCipherSuite() throws NoCSFoundException;
	
	public short selectCompressionMethod() throws NoCMFoundException;

//	public List<Extension> getClientHelloExtensions();

	public void setOfferedExtensions(List<Extension> extensions);

	public List<Extension> selectExtensions(boolean client);

	public void verifyServerKeyExchange(ServerKeyExchangeAlgorithm keyExchange) throws SignatureNotValidException, ProgramErrorException;

	public void selectKeyExchangeMethod() throws ProgramErrorException;

	public void calculatePreMasterSecret(byte[] exchange_keys) throws ProgramErrorException;

	public Key getSigningKey();

	public void setCookie(byte[] cookie);
	
	public byte[] getCookie();

}
