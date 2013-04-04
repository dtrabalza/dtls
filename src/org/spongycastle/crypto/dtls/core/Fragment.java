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



import org.spongycastle.crypto.dtls.constants.HandshakeType;
import org.spongycastle.crypto.dtls.core.handshake.Certificate;
import org.spongycastle.crypto.dtls.core.handshake.CertificateRequest;
import org.spongycastle.crypto.dtls.core.handshake.CertificateVerify;
import org.spongycastle.crypto.dtls.core.handshake.ClientHello;
import org.spongycastle.crypto.dtls.core.handshake.ClientKeyExchange;
import org.spongycastle.crypto.dtls.core.handshake.Finished;
import org.spongycastle.crypto.dtls.core.handshake.HelloVerifyRequest;
import org.spongycastle.crypto.dtls.core.handshake.ServerHello;
import org.spongycastle.crypto.dtls.core.handshake.ServerKeyExchange;
import org.spongycastle.crypto.dtls.exceptions.NoCMFoundException;
import org.spongycastle.crypto.dtls.exceptions.NoCSFoundException;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.interfaces.FragmentType;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;

/**
 * This class represents a Frame of the
 * DTLS protocol (RFC 6347) to handle
 * packet fragmentation for handshake messages
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class Fragment implements FragmentType, Comparable<Fragment>{

	//1 byte
	private short message_type;
	//3 bytes
	private int length;		//this is the length of the whole body
	//2 bytes
	private int message_sequence;
	//3 bytes
	private int fragment_offset;
	//3 bytes
	private int fragment_length;
	
	HandshakeMessage body;
	
	public Fragment() {
		
	}

	public short getMessage_type() {
		return message_type;
	}

	public void setMessage_type(short message_type) {
		this.message_type = message_type;
	}

	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		this.length = length;
	}

	public int getMessage_sequence() {
		return message_sequence;
	}

	public void setMessage_sequence(int message_sequence) {
		this.message_sequence = message_sequence;
	}

	public int getFragment_offset() {
		return fragment_offset;
	}

	public void setFragment_offset(int fragment_offset) {
		this.fragment_offset = fragment_offset;
	}

	public int getFragment_length() {
		return fragment_length;
	}

	public void setFragment_length(int fragment_length) {
		this.fragment_length = fragment_length;
	}

	public HandshakeMessage getBody() {
		return body;
	}

	public void setBody(HandshakeMessage body) {
		this.body = body;
	}
	
	public int getTotalByteLength(){
		int l = 12;	//static fields
		if (body != null)
			l += body.getTotalByteLength();
		return l;
	}

	/**
	 * Creates and returns a new Fragment containing a client_hello message
	 * @param context
	 * @param cookie 
	 * @return
	 */
	public static Fragment newClientHello(DTLSContext context, byte[] cookie) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.client_hello);
		HandshakeMessage clientHello = ClientHello.newClientHello(context, cookie); 
		fragment.setBody(clientHello);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(clientHello.getTotalByteLength());
		
		//length
		fragment.setLength(clientHello.getTotalByteLength());

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}

	/**
	 * Creates and returns a new Fragment containing a
	 * helloVerifyReuest message
	 * @param cookie 
	 * @return
	 */
	public static Fragment getNewHelloVerifyRequest(byte[] cookie) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.hello_verify_request);
		
		HandshakeMessage helloVerifyRequest = HelloVerifyRequest.newHelloVerifyRequest(cookie);
		fragment.setBody(helloVerifyRequest);
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(helloVerifyRequest.getTotalByteLength());
		
		//length
		fragment.setLength(helloVerifyRequest.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}
	
	public static Fragment newServerHello(DTLSContext context) throws NoCSFoundException, NoCMFoundException {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.server_hello);
		
		HandshakeMessage serverHello = ServerHello.newServerHello(context);
		fragment.setBody(serverHello);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(serverHello.getTotalByteLength());
		
		//length
		fragment.setLength(serverHello.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}

	/**
	 * Creates and return a new Certificate fragment
	 * based on the parameters in the context
	 * @param context
	 * @return
	 */
	public static Fragment newCertificate(DTLSContext context, boolean isClient) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.certificate);
		
		HandshakeMessage certificate = Certificate.newCertificate(context, isClient);
		fragment.setBody(certificate);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(certificate.getTotalByteLength());
		
		//length
		fragment.setLength(certificate.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}
	
	/**
	 * Creates and return a ServerHelloDone fragment
	 * @return
	 */
	public static Fragment newServerHelloDone() {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.server_hello_done);
		
		//no need to fragment here

		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(0);
		
		//length
		fragment.setLength(0);
		
		return fragment;
	}
	
	/**
	 * 
	 * @param exchange_keys 
	 * @return
	 */
	public static Fragment newClientKeyExchange(byte[] exchange_keys) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.client_key_exchange);
		
		HandshakeMessage clientKeyExchange = ClientKeyExchange.newClientKeyExchange(exchange_keys);
		fragment.setBody(clientKeyExchange);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(clientKeyExchange.getTotalByteLength());
		
		//length
		fragment.setLength(clientKeyExchange.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}
	
	/**
	 * 
	 * @param context
	 * @param verify_data 
	 * @return
	 */
	public static FragmentType newFinished(DTLSContext context, byte[] verify_data) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.finished);
		
		HandshakeMessage finished = Finished.newFinished(context, verify_data);
		fragment.setBody(finished);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(finished.getTotalByteLength());
		
		//length
		fragment.setLength(finished.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}
	
	/**
	 * Creates and returns a new certificate request message
	 * @param context
	 * @return
	 */
	public static FragmentType newCertificateRequest(DTLSContext context) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.certificate_request);
		
		HandshakeMessage certificateRequest = CertificateRequest.newCertificateRequest(context);
		fragment.setBody(certificateRequest);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(certificateRequest.getTotalByteLength());
		
		//length
		fragment.setLength(certificateRequest.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}

//	@Override
//	public String toString() {
//		String result = "";
//		result += DTLSUtils.byteToBits(new Short(message_type).byteValue()) + "";
//		result += DTLSUtils.printBytes((DTLSUtils.getBytesFromValue(length, 3))) + "";
//		result += DTLSUtils.printBytes((DTLSUtils.getBytesFromValue(message_sequence, 2	))) + "";
//		result += DTLSUtils.printBytes((DTLSUtils.getBytesFromValue(fragment_offset, 3))) + "";
//		result += DTLSUtils.printBytes((DTLSUtils.getBytesFromValue(fragment_length, 3))) + "";
//		result += body.toString();
//		return result;
//	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((body == null) ? 0 : body.hashCode());
		result = prime * result + fragment_length;
		result = prime * result + fragment_offset;
		result = prime * result + length;
		result = prime * result + message_sequence;
		result = prime * result + message_type;
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
		Fragment other = (Fragment) obj;
		if (body == null) {
			if (other.body != null)
				return false;
		} else if (!body.equals(other.body))
			return false;
		if (fragment_length != other.fragment_length)
			return false;
		if (fragment_offset != other.fragment_offset)
			return false;
		if (length != other.length)
			return false;
		if (message_sequence != other.message_sequence)
			return false;
		if (message_type != other.message_type)
			return false;
		return true;
	}

	@Override
	public String toString() {
		String result = "";
		result += "MessageType: " + message_type;
		if (body != null)
			result += body.toString();
		else
			result += "Body not present";
		return result;
	}

	@Override
	public int compareTo(Fragment fragment) {
		return new Integer(message_sequence).compareTo(fragment.getMessage_sequence());
	}

	public static FragmentType newServerKeyExchange(DTLSContext context, org.spongycastle.crypto.dtls.interfaces.ServerKeyExchangeAlgorithm keyExchange) {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.server_key_exchange);
		
		HandshakeMessage serverKeyExchange = ServerKeyExchange.newServerKeyExchange(context, keyExchange);
		fragment.setBody(serverKeyExchange);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(serverKeyExchange.getTotalByteLength());
		
		//length
		fragment.setLength(serverKeyExchange.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}

	public static FragmentType newCertificateVerify() {
		Fragment fragment = new Fragment();
		fragment.setMessage_type(HandshakeType.certificate_verify);
		
		HandshakeMessage certificateVerify = CertificateVerify.newCertificateVerify();
		fragment.setBody(certificateVerify);

		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  BEGIN
		*/
		//TODO: implement fragmentation
		
		//message_sequence = 0
		//fragment_offset = 0
		
		//fragment lenght
		fragment.setFragment_length(certificateVerify.getTotalByteLength());
		
		//length
		fragment.setLength(certificateVerify.getTotalByteLength());
		
		/* ASSUMED NO FRAGMENTATION
		*  with no fragmentation fragment_length=length
		*  length is the dimension of the whole handshake message
		*  fragment_length is the length of the current fragment
		*  
		*  END
		*/
		
		return fragment;
	}

}
