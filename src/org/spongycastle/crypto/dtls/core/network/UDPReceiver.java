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
package org.spongycastle.crypto.dtls.core.network;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

import org.spongycastle.crypto.dtls.interfaces.Receiver;

public class UDPReceiver implements Receiver {

	@Override
	public InetAddress receive(int port, byte[] buf, int timeout) throws SocketTimeoutException{
		DatagramSocket datagramSocket = null;
		try{
			//Receiving socket on the UDP port specified
			datagramSocket = new DatagramSocket(port);
			
			if (timeout != 0)
				datagramSocket.setSoTimeout(timeout);
			
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			
			datagramSocket.receive(packet);

			return packet.getAddress();

		}catch (Exception e) {
			if (e instanceof SocketTimeoutException)
				throw (SocketTimeoutException)e;
			else
				System.out.println("Exception during reception: " + e.getMessage());
			
			return null;
		}finally{
			//in any case close the socket
			datagramSocket.close();
		}
	}

}
