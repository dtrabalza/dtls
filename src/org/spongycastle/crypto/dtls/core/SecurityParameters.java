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

import java.nio.ByteBuffer;
import java.util.logging.Logger;

import org.spongycastle.crypto.dtls.utils.DTLSUtils;
import org.spongycastle.util.Strings;

/**
 * This class represents the DTLS security parameters
 * 
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class SecurityParameters {
	
	private static final Logger LOG = Logger.getLogger(SecurityParameters.class.getName());

	//client random 
	private byte[] clientRandom = null;
	//server random
	private byte[] serverRandom = null;
	//master secret
	private byte[] masterSecret = null;
	
	//lenght of the encryption key
	private int encKeyLength;
	//client write key
	private byte[] client_write_key;
	//server write key
	private byte[] server_write_key;
					
	//length of the client IV
	private int client_write_IV_length;
	//client_IV
	private byte[] client_write_IV;

	//length of the server IV
	private int server_write_IV_length;
	//server_IV
	private byte[] server_write_IV;
	
	
	public SecurityParameters() {
		
	}
	
	/**
	 * 
	 */
	public void generateSessionKeys() {
		int sessionKeysTotLength =  
				(2 * encKeyLength) +  //client_write_key + server_write_key
				+ client_write_IV_length 	//length of the client IV
				+ server_write_IV_length;	//length of the server IV
				//ADD MAC CLIENT AND SERVER. Not used for CCM
		
		//generating key material
		ByteBuffer keyGroup = ByteBuffer.allocate(sessionKeysTotLength);
		keyGroup.put(DTLSUtils.PRF(masterSecret, 
				Strings.toByteArray("key expansion"), 
				DTLSUtils.concat(serverRandom, clientRandom),
				sessionKeysTotLength));
		
		keyGroup.flip();
		
		//splitting the key material
		//byte arrays already initialized during set length
		//client MAC
		//server MAC
		keyGroup.get(client_write_key);
		keyGroup.get(server_write_key);
		keyGroup.get(client_write_IV);
		keyGroup.get(server_write_IV);
		
		LOG.finest("client_write_key: " + DTLSUtils.getHexString(client_write_key));
		
		LOG.finest("server_write_key: " + DTLSUtils.getHexString(server_write_key));
		
		LOG.finest("client_write_IV: " + DTLSUtils.getHexString(client_write_IV));
		
		LOG.finest("server_write_IV: " + DTLSUtils.getHexString(server_write_IV));
	}

	public void setMasterSecret(byte[] masterSecret) {
		this.masterSecret = masterSecret;
	}

	public byte[] getMasterSecret() {
		return masterSecret;
	}

	public byte[] getClientRandom() {
		return clientRandom;
	}

	public void setClientRandom(byte[] clientRandom) {
		this.clientRandom = clientRandom;
	}

	public byte[] getServerRandom() {
		return serverRandom;
	}

	public void setServerRandom(byte[] serverRandom) {
		this.serverRandom = serverRandom;
	}

	public int getEncKeyLength() {
		return encKeyLength;
	}

	public void setEncKeyLength(int encKeyLength) {
		this.encKeyLength = encKeyLength;
		this.client_write_key = new byte[encKeyLength];
		this.server_write_key = new byte[encKeyLength];
	}

	public byte[] getClient_write_key() {
		return client_write_key;
	}

	public void setClient_write_key(byte[] client_write_key) {
		this.client_write_key = client_write_key;
	}

	public byte[] getServer_write_key() {
		return server_write_key;
	}

	public void setServer_write_key(byte[] server_write_key) {
		this.server_write_key = server_write_key;
	}

	public int getClient_write_IV_length() {
		return client_write_IV_length;
	}

	public void setClient_write_IV_length(int client_write_IV_length) {
		this.client_write_IV_length = client_write_IV_length;
		this.client_write_IV = new byte[client_write_IV_length];
	}

	public byte[] getClient_write_IV() {
		return client_write_IV;
	}

	public void setClient_write_IV(byte[] client_write_IV) {
		this.client_write_IV = client_write_IV;
	}

	public int getServer_write_IV_length() {
		return server_write_IV_length;
	}

	public void setServer_write_IV_length(int server_write_IV_length) {
		this.server_write_IV_length = server_write_IV_length;
		this.server_write_IV = new byte[server_write_IV_length];
	}

	public byte[] getServer_write_IV() {
		return server_write_IV;
	}

	public void setServer_write_IV(byte[] server_write_IV) {
		this.server_write_IV = server_write_IV;
	}
	
}
