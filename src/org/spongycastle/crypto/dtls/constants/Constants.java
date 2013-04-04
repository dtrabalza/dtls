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

public class Constants {
	
	public final static int DEFAULT_PORT = 4433;
	
	//client version: DTLS 1.2
	public static short CLIENT_VERSION_MAJOR = 1;
	public static short CLIENT_VERSION_MINOR = 2;	//test
	
	//server version: DTLS 1.2
	public static final short SERVER_VERSION_MAJOR = 1;
	public static final short SERVER_VERSION_MINOR = 2; //test
	
	//base version of DTLS 1.2 server
	public static final short SERVER_BASE_VERSION_MAJOR = 1;
	public static final short SERVER_BASE_VERSION_MINOR = 2;
	
	//by default the cookie is 32 bit long
	public static int COOKIE_LENGTH = 32;
	
	
	/**
	 * This is the retransmission timer for the DTLS protocol.
	 * Do not modify this value unless you are completely confident
	 * of what you are doing. It can congest a link.
	 * Explanations in RFC 6347 4.2.4.1
	 */
	public static int RETRANSMISSION_TIME = 1 * 1000;
	
	public static int RECEIVING_BUFFER_SIZE = 1500;
	
	public static final int SEND_BUFFER_SIZE = 1500;

	public static final int DATA_BUFFER_SIZE = 1500;

	
}
