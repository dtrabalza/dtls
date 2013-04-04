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
package org.spongycastle.crypto.dtls.core.context;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.spongycastle.crypto.dtls.core.RecordLayer;
import org.spongycastle.crypto.dtls.core.handshake.DistinguishedName;
import org.spongycastle.crypto.dtls.core.handshake.Extension;
import org.spongycastle.crypto.dtls.exceptions.SignatureNotValidException;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.ServerKeyExchangeAlgorithm;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;

public class DTLSPSKContext extends DTLSAbstractContext implements DTLSContext {

	// list of pre shared keys with psk identities
	private Map<String, byte[]> preSharedKeys;

	private String pskIdentity;

	public DTLSPSKContext() {

	}

	public void init(Map<String, byte[]> preSharedKeys, SecureRandom random) {
		this.preSharedKeys = preSharedKeys;
		super.init(random);
	}

	public String getPskIdentity() {
		return pskIdentity;
	}

	public void setPskIdentity(String psk_identity) {
		this.pskIdentity = psk_identity;
	}

	public Map<String, byte[]> getPreSharedKeys() {
		return preSharedKeys;
	}

	public RecordLayer getClientKeyExchange() {
		selectPSKID();
		RecordLayer clientKeyExchange = RecordLayer.getNewClientKeyExchange(pskIdentity.getBytes());
		return clientKeyExchange;
	}

	private void selectPSKID() {
		if (pskIdentity == null || pskIdentity == ""){
			//the server didn't specify any psk_identity_hint, so
			//take the first one
			pskIdentity = preSharedKeys.keySet().iterator().next();
			System.out.println("PSK_ID = " + pskIdentity);
		}
	}

	@Override
	/**
	 * RFC 4279 section 2
	 * 
	 * bytes are signed so the next byte of 127 is -128!
	 */
	public byte[] getPreMasterSecret() {
		if (preSharedKeys == null)
			return super.getPreMasterSecret();
		
		/*
		 * length = 2N+4
		 */
		selectPSKID();

		byte[] psk = preSharedKeys.get(pskIdentity); 
		byte[] preMasterSecret; //= new byte[2*(psk.length)+4];

		//first two octects
		byte[] twoOctects = DTLSUtils.getBytesFromValue(psk.length, 2);
		
		//N octects
		byte[] zeroPaddedArray = Arrays.copyOfRange(new byte[]{}, 0, psk.length);
		
		preMasterSecret = DTLSUtils.concat(twoOctects, zeroPaddedArray);
		
		preMasterSecret = DTLSUtils.concat(preMasterSecret, twoOctects);
		
		preMasterSecret = DTLSUtils.concat(preMasterSecret, psk);
		
		LOG.info("PreMasterSecret: " + DTLSUtils.getHexString(preMasterSecret));
		
		return preMasterSecret;
	}

	public List<Extension> getClientHelloExtensions() {
		//no extensions needed here
		return null;
	}

	@Override
	public Key getSigningKey() {
		//not used here
		return null;
	}

	@Override
	public void verifyServerKeyExchange(ServerKeyExchangeAlgorithm keyExchange)
			throws SignatureNotValidException {
		//nothing to do with pre-shared key
	}

	@Override
	public List<DistinguishedName> getValidDN() {
		return null;
	}



}
