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
package org.spongycastle.crypto.dtls.constants;

import java.util.logging.Logger;

import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;

/**
 * This class defines the states of the DTLS Protocol
 * 
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class ProtocolState {

	private static final Logger LOG = Logger.getLogger(ProtocolState.class
			.getName());

	/**
	 * Just created the object but before send or receive any message. In this
	 * state the protocol is never used, neither by the client nor by the
	 * server, so it doesn't know yet if it must act as a client or server.
	 */
	public static final int INITIAL_STATE = 0;

	/**
	 * This indicates that the handshake is finished and the security parameters
	 * between client and server are exchanged correctly. Data can be now
	 * correctly encrypted and send/received
	 */
	public static final int HANDSHAKE_COMPLETED = 1000;

	public static final int CHANGE_CIPHER_SPEC_RECEIVED = 8;

	public static final int FIRST_CLIENT_HELLO_RECEIVED = 10;

	public static final int FIRST_CLIENT_HELLO_SENT = 15;

	public static final int SECOND_CLIENT_HELLO_RECEIVED = 20;

	public static final int SECOND_CLIENT_HELLO_SENT = 25;

	public static final int HELLO_VERIFY_REQUEST_RECEIVED = 30;

	public static final int HELLO_VERIFY_REQUEST_SENT = 35;

	public static final int SERVER_HELLO_RECEIVED = 40;

	public static final int SERVER_HELLO_SENT = 45;

	public static final int CLIENT_CERTIFICATE_RECEIVED = 50;

	public static final int CLIENT_CERTIFICATE_SENT = 55;

	public static final int SERVER_CERTIFICATE_RECEIVED = 60;

	public static final int SERVER_CERTIFICATE_SENT = 65;

	public static final int SERVER_KEY_EXCHANGE_RECEIVED = 70;

	public static final int SERVER_KEY_EXCHANGE_SENT = 75;

	public static final int CERTIFICATE_REQUEST_RECEIVED = 80;

	public static final int CERTIFICATE_REQUEST_SENT = 85;

	public static final int SERVER_HELLO_DONE_RECEIVED = 90;

	public static final int SERVER_HELLO_DONE_SENT = 95;

	public static final int CLIENT_KEY_EXCHANGE_RECEIVED = 100;

	public static final int CLIENT_KEY_EXCHANGE_SENT = 105;

	public static final int CERTIFICATE_VERIFY_RECEIVED = 110;

	public static final int CERTIFICATE_VERIFY_SENT = 115;

	public static final int FINISHED_RECEIVED = 120;

	public static final int FINISHED_SENT = 125;

	public static void logProtocolStateChange(int newProtocolState) throws ProgramErrorException {
		switch (newProtocolState) {
		
		case ProtocolState.INITIAL_STATE:
			LOG.fine("Protocol state changed to: INITIAL_STATE");
			break;

		case ProtocolState.HANDSHAKE_COMPLETED :
			LOG.fine("Protocol state changed to: HANDSHAKE_COMPLETED");
			break;

		case ProtocolState.CHANGE_CIPHER_SPEC_RECEIVED :
			LOG.fine("Protocol state changed to: CHANGE_CIPHER_SPEC_RECEIVED");
			break;

		case ProtocolState.FIRST_CLIENT_HELLO_RECEIVED :
			LOG.fine("Protocol state changed to: FIRST_CLIENT_HELLO_RECEIVED");
			break;

		case ProtocolState.FIRST_CLIENT_HELLO_SENT :
			LOG.fine("Protocol state changed to: FIRST_CLIENT_HELLO_SENT");
			break;

		case ProtocolState.SECOND_CLIENT_HELLO_RECEIVED :
			LOG.fine("Protocol state changed to: SECOND_CLIENT_HELLO_RECEIVED");
			break;

		case ProtocolState.SECOND_CLIENT_HELLO_SENT :
			LOG.fine("Protocol state changed to: SECOND_CLIENT_HELLO_SENT");
			break;

		case ProtocolState.HELLO_VERIFY_REQUEST_RECEIVED :
			LOG.fine("Protocol state changed to: HELLO_VERIFY_REQUEST_RECEIVED");
			break;

		case ProtocolState.HELLO_VERIFY_REQUEST_SENT :
			LOG.fine("Protocol state changed to: HELLO_VERIFY_REQUEST_SENT");
			break;

		case ProtocolState.SERVER_HELLO_RECEIVED :
			LOG.fine("Protocol state changed to: SERVER_HELLO_RECEIVED");
			break;

		case ProtocolState.SERVER_HELLO_SENT :
			LOG.fine("Protocol state changed to: SERVER_HELLO_SENT");
			break;

		case ProtocolState.CLIENT_CERTIFICATE_RECEIVED :
			LOG.fine("Protocol state changed to: CLIENT_CERTIFICATE_RECEIVED");
			break;

		case ProtocolState.CLIENT_CERTIFICATE_SENT :
			LOG.fine("Protocol state changed to: CLIENT_CERTIFICATE_SENT");
			break;

		case ProtocolState.SERVER_CERTIFICATE_RECEIVED :
			LOG.fine("Protocol state changed to: SERVER_CERTIFICATE_RECEIVED");
			break;

		case ProtocolState.SERVER_CERTIFICATE_SENT :
			LOG.fine("Protocol state changed to: SERVER_CERTIFICATE_SENT");
			break;

		case ProtocolState.SERVER_KEY_EXCHANGE_RECEIVED :
			LOG.fine("Protocol state changed to: SERVER_KEY_EXCHANGE_RECEIVED");
			break;
			
		case ProtocolState.SERVER_KEY_EXCHANGE_SENT :
			LOG.fine("Protocol state changed to: SERVER_KEY_EXCHANGE_SENT");
			break;
			
		case ProtocolState.CERTIFICATE_REQUEST_RECEIVED :
			LOG.fine("Protocol state changed to: CERTIFICATE_REQUEST_RECEIVED");
			break;
			
		case ProtocolState.CERTIFICATE_REQUEST_SENT :
			LOG.fine("Protocol state changed to: CERTIFICATE_REQUEST_SENT");
			break;
			
		case ProtocolState.SERVER_HELLO_DONE_RECEIVED :
			LOG.fine("Protocol state changed to: SERVER_HELLO_DONE_RECEIVED");
			break;
			
		case ProtocolState.SERVER_HELLO_DONE_SENT :
			LOG.fine("Protocol state changed to: SERVER_HELLO_DONE_SENT");
			break;

		case ProtocolState.CLIENT_KEY_EXCHANGE_RECEIVED :
			LOG.fine("Protocol state changed to: CLIENT_KEY_EXCHANGE_RECEIVED");
			break;

		case ProtocolState.CLIENT_KEY_EXCHANGE_SENT :
			LOG.fine("Protocol state changed to: CLIENT_KEY_EXCHANGE_SENT");
			break;

		case ProtocolState.CERTIFICATE_VERIFY_RECEIVED :
			LOG.fine("Protocol state changed to: CERTIFICATE_VERIFY_RECEIVED");
			break;

		case ProtocolState.CERTIFICATE_VERIFY_SENT :
			LOG.fine("Protocol state changed to: CERTIFICATE_VERIFY_SENT");
			break;

		case ProtocolState.FINISHED_RECEIVED :
			LOG.fine("Protocol state changed to: FINISHED_RECEIVED");
			break;

		case ProtocolState.FINISHED_SENT :
			LOG.fine("Protocol state changed to: FINISHED_SENT");
			break;
			
		default:
			throw new ProgramErrorException("Illegal protocol state");
		}

		
	}
}
