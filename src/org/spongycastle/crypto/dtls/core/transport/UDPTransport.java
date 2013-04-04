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
package org.spongycastle.crypto.dtls.core.transport;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.spongycastle.crypto.dtls.constants.Constants;

/**
 * This class implements the datagram reception.
 * Continuously receives datagrams and publishes
 * with the observer pattern whenever there is
 * a new reception
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class UDPTransport {
	
	private static final Logger LOG = Logger.getLogger(UDPTransport.class.getName());
	
	//receiving socket
	private DatagramSocket socket;
	
	//listeners for data reception
	private List<IncomingDataListener> listeners;	
	
	public UDPTransport(int port) throws SocketException {
		
		//initialize the list of listeners
		listeners = new ArrayList<IncomingDataListener>();
				
		//create a socket on the specified sending port
		socket = new DatagramSocket(port);
		
		//start the receiving thread
		ReceiverThread thread = new ReceiverThread();
		thread.start();
		LOG.finest("Receiving Thread started");
	}
	
	/**
	 * This method adds a subscriber that wants to be updated
	 * when new data are received
	 * @param lis the class that implements IncomingDataListener
	 */
	public void addIncomingDataListener(IncomingDataListener lis){
		this.listeners.add(lis);
	}
	
	/**
	 * This method publish a property event to all the subscribers
	 * @param sender the object that generates the notification
	 * @param value the value of the notification
	 */
	private void publishPropertyEvent(Object sender, Object value){
		for (IncomingDataListener subscriber : listeners) {
			subscriber.onPropertyEvent(sender, value);
		}
	}

	/**
	 * Class that hosts the thread that receives continuously
	 * datagrams and publish the event when a new datagram is
	 * received through the observer pattern
	 *
	 * @author Daniele Trabalza <daniele@sics.se>
	 */
	public class ReceiverThread extends Thread{
		
		public ReceiverThread() {
			super("Receiver Thread");
		}
		
		@Override
		public void run() {
			
			//always receive datagrams
			while (true){

				// allocate buffer
				byte[] buffer = new byte[Constants.RECEIVING_BUFFER_SIZE]; 

				final DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
				
				try {
					socket.receive(datagram);
				} catch (IOException e) {
					LOG.severe("Exception receiving datagram " + e.getMessage());
					
					//keep receiving
					continue;
				}
				
				//notify the reception of the datagram
				LOG.finest("UDPTransport: Datagram received");
				//notify in a new thread
				new Thread(new Runnable() {
					
					@Override
					public void run() {
						publishPropertyEvent(this, datagram);
						
					}
				}).start();
				
			}
		}
	}

	/**
	 * This method sends a datagram to the address and
	 * port specified
	 * @param address the destination of the datagram
	 * @param sendingPort the destination port
	 * @param data data to be send as payload 
	 * @throws IOException
	 */
	public void send(InetAddress address, int port, byte[] data) throws IOException {
		
		if (data.length == 0){
			LOG.warning("Trying to send empty data");
			return;
		}
		//packet to send
		DatagramPacket packet = new DatagramPacket(data, data.length, address, port);
		
		//sending
		socket.send(packet);
		
		LOG.finest("UDPTransport: Datagram sent to " + address.getCanonicalHostName() +":" + port);

	}
}
