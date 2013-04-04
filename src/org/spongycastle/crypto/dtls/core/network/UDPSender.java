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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import org.spongycastle.crypto.dtls.interfaces.Sender;

public class UDPSender implements Sender {

	@Override
	public boolean send(InetAddress address, int port, byte[] data, int length, int timeout){
		
		DatagramSocket datagramSocket = null;
		
		try {
			//packet to send
			DatagramPacket packet = new DatagramPacket(data, length, address, port);
			
			//TODO: bind outgoing socket to the same port?
			datagramSocket = new DatagramSocket();
//			datagramSocket = new DatagramSocket(4433);
			
			//set the timeout
			//temporary disabled
//			datagramSocket.setSoTimeout(timeout);
			
			datagramSocket.send(packet);

			//Successfully transmitted
			return true;	
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			//errors during the transmission
			return false;
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			//errors during the transmission
			return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			//errors during the transmission
			return false;
		}finally{
			datagramSocket.close();
		}
		
	}

}
