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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.dtls.DTLSConnector;
import org.spongycastle.crypto.dtls.constants.Constants;
import org.spongycastle.crypto.dtls.constants.ContentType;
import org.spongycastle.crypto.dtls.constants.HandshakeType;
import org.spongycastle.crypto.dtls.constants.ProtocolState;
import org.spongycastle.crypto.dtls.core.ciphers.DTLSNullCipher;
import org.spongycastle.crypto.dtls.core.compressions.DTLSNullCompression;
import org.spongycastle.crypto.dtls.core.context.DTLSECCContext;
import org.spongycastle.crypto.dtls.core.handshake.Certificate;
import org.spongycastle.crypto.dtls.core.handshake.CertificateVerify;
import org.spongycastle.crypto.dtls.core.handshake.ClientHello;
import org.spongycastle.crypto.dtls.core.handshake.ClientKeyExchange;
import org.spongycastle.crypto.dtls.core.handshake.Finished;
import org.spongycastle.crypto.dtls.core.handshake.HelloVerifyRequest;
import org.spongycastle.crypto.dtls.core.handshake.ServerHello;
import org.spongycastle.crypto.dtls.core.handshake.ServerKeyExchange;
import org.spongycastle.crypto.dtls.core.transport.IncomingDataListener;
import org.spongycastle.crypto.dtls.core.transport.UDPTransport;
import org.spongycastle.crypto.dtls.exceptions.DecryptionException;
import org.spongycastle.crypto.dtls.exceptions.EncryptionException;
import org.spongycastle.crypto.dtls.exceptions.NoCMFoundException;
import org.spongycastle.crypto.dtls.exceptions.NoCSFoundException;
import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;
import org.spongycastle.crypto.dtls.exceptions.SignatureNotValidException;
import org.spongycastle.crypto.dtls.interfaces.DTLSCipher;
import org.spongycastle.crypto.dtls.interfaces.DTLSCompression;
import org.spongycastle.crypto.dtls.interfaces.DTLSContext;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;
import org.spongycastle.crypto.tls.AlertDescription;
import org.spongycastle.crypto.tls.AlertLevel;
import org.spongycastle.util.Strings;

/**
 * This is the main class that handles the DTLS protocol.
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class DTLSProtocolHandler implements IncomingDataListener{
	
	private static final Logger LOG = Logger.getLogger(DTLSProtocolHandler.class.getName());
	
	//address of the client
	private InetAddress address = null;
	//protocol port
	private int port;
	
	/*
	 * We need two parser. Since the reading and writing
	 * state might be different, the parsing is also
	 * different since we might read a plaintext record and write
	 * an encoded record
	 */
	//parser for reading records
	private DTLSParser parser;
	
	//Transport protocol
	//TODO: generalize
	UDPTransport transport;
	
	//queue where datagrams received in the transport are put
	private LinkedBlockingDeque<DatagramPacket> datagramqueue;

//	//Sender
//	@Deprecated
//	private Sender sender;
	
//	//Receiver
//	@Deprecated
//	private Receiver receiver;
	
	//context, containing keys, certificates and random number 
	private DTLSContext context;
	
	// represents one of the state of the protocol
	// see ProtocolState
	private int protocolState;
	
	//this buffer is used to send data messages
	//this is done in order to buffer the send message
	//in the meantime the handshake is taking place
	private ByteBuffer dataBuffer;
	
	//flights that has been transmitted to the peer
	private List<RecordLayer> transmittedRecords;
	
	//received flights
	private List<RecordLayer> receivedRecords;
	
	//records with epoch greater than the current
	private PriorityQueue<RecordLayer> nextEpochQueue;
	
	//queue of application data
	private PriorityQueue<RecordLayer> appDataQueue;
	
	//queue of alerts messages
	private PriorityQueue<RecordLayer> alertQueue;
		
	//queue of handshake messages
	private PriorityQueue<RecordLayer> handshakeQueue;
	
	//current flights about to be sent
	//contains the same value of the handshakeBuffer
	//but the object structure instead of a byte array
	private List<RecordLayer> preparedRecords;
	
	//this is the epoch field incremented every ChangeCipherSpec
	//in this implementation packets out of the current epoch are discarded
	private int currentWriteEpoch;
	
	//reading epoch
	private int currentReadEpoch;
	
	//field incremented every time there is a transmission or retransmission
	//starts from 0; set again to 0 when epoch increases
	private int writingSequenceNumber;
	
	private int expectedSequenceNumber;
	
	//message sequence determining the status of the handshake
	private int writingMessageSequence;
	
	//last received message sequence (reading)
	private int expectedMessageSequence = 0;

	//indicates whether this handler is used by a client or a server
	private boolean isClient;
	
	//current cipher suites
	private DTLSCipher readCipher;
	private DTLSCipher writeCipher;
	
	//current compression methods
	private DTLSCompression readCompression;
	private DTLSCompression writeCompression;
	
	//cipher suites to be used in the next epoch
	private DTLSCipher pendingReadCipher;
	private DTLSCipher pendingWriteCipher;
	
	//compression methods to be used in the next epoch
	private DTLSCompression pendingReadCompression;
	private DTLSCompression pendingWriteCompression;
	
	//hash
	//TODO: generalize
	private Digest hash;
	private Digest sha1Hash;
	
	//retransmission timer
	private Timer retransmissionTimer;

	//plain text received, decrypted and decompressed
	private List<byte[]> receivedData;
	
//	/*
//	 * this variable specifies when the whole flight has been received, 
//	 * since records can be sent in separate datagrams
//	 */
//	private boolean wholeFlightReceived = false;
	
	/*
	 * This variable indicates if the records must be sent
	 * in the same datagram or in different datagrams.
	 * The reception must work in either ways 
	 */
	private final boolean sendSeparately = false;
	
	//field that specifies if the protocol requires mutual authentication
	//server side
	private boolean mutualAuth =  false;

	//subscribers that are interested on state change
	private List<DTLSConnector> subscribers;

	//true if the server or client must send the certificate
	//TODO: set to false and put true whenever needed
	private boolean mustSendCertificate = true;

	//true if the server must send a client key exchange message
	//TODO: set to false and put true whenever needed
	private boolean mustSendServerKeyExchange = true;

	//true if the client needs to send the client key exchange
	//TODO: set to false and put true whenever needed
	private boolean clientKeyExchangeNeeded = true;

	/*
	 * True if the client has the capability to sign data
	 * this is possible if the client has a private key in
	 * addition to the certificate
	 */
	//TODO: set to false and put true whenever needed
	private boolean clientCanSign = true;

	/*
	 * This variable represents the time when the waiting state
	 * started the first time. It is used to handle partial
	 * reception of data, that do not reset the retransmission
	 * timer
	 */
	private long startOfWaitingState;

	/*
	 * This variable is used to determine if a
	 * received datagram should be immediately
	 * parsed. This happens when the handshake 
	 * is completed, and both client and server
	 * must decrypt and validate the application 
	 * data and return it to the upper layers
	 * It must be false in the beginning: then
	 * when the handshake is completed, it is
	 * set to true. 
	 * When the sever wants to rehandshake, this
	 * variable is set back to false, and the 
	 * rehandsake is performed; at the end
	 * it will be set again to true, and so on... 
	 */
	private boolean processDirectly = false;
	
	/**
	 * InetAddress address contains the address of the client
	 * or the server. If the address is localhost or null
	 * only the port will be taken, if null it will be
	 * used the default port. If it contains a valid address
	 * it will represent the client and will be used to send
	 * messages to the client
	 * 
	 * @param address the address of the client. If null this instance
	 * is a server
	 * @param port protocol port
	 * @throws UnknownHostException if the address is not valid
	 * @throws SocketException 
	 */
	public DTLSProtocolHandler(int port, DTLSContext context, boolean isDTLSClient) throws SocketException {
		//determines if this is a server or a client
		this.isClient = isDTLSClient;
		LOG.config("This is a DTLS " + 
				new String((isDTLSClient) ? "client" : "server"));
		
		//if the port is omitted, it will be used the default port
		if (port == 0)
			this.port = Constants.DEFAULT_PORT;
		else
			this.port = port;
		LOG.config("Port set to " + this.port);
				
		//initialize context
		this.context = context;
		
		//initialization
		init();
	}

	/**
	 * Initializes the protocol at the initial state, to be
	 * ready to start a NEW handshake for the first time
	 * @throws SocketException 
	 */
	private void init() throws SocketException {
		//the state is the initial state
		this.protocolState = ProtocolState.INITIAL_STATE;
		
		//allocate the buffers
		if (dataBuffer == null)
			dataBuffer = ByteBuffer.allocate(Constants.DATA_BUFFER_SIZE);
		
		//initialize variables
		transmittedRecords = new ArrayList<RecordLayer>();
		receivedRecords = new ArrayList<RecordLayer>();
		preparedRecords = new ArrayList<RecordLayer>();
		nextEpochQueue = new PriorityQueue<RecordLayer>();
		appDataQueue = new PriorityQueue<RecordLayer>();
		alertQueue = new PriorityQueue<RecordLayer>();
		receivedData = new ArrayList<byte[]>();
		handshakeQueue = new PriorityQueue<RecordLayer>();
		datagramqueue = new LinkedBlockingDeque<DatagramPacket>();
		currentWriteEpoch = 0;
		
		//null cipher suite TLS_WITH_NULL_NULL in the first handshake
		readCipher = new DTLSNullCipher();
		writeCipher = new DTLSNullCipher();
		readCompression = new DTLSNullCompression();
		writeCompression = new DTLSNullCompression();
		
		//initialize default hashing
		hash = new SHA256Digest();
		sha1Hash = new SHA1Digest();
		
		//parser
		parser = new DTLSParser();

		/*
		 * The transport will continuously receive datagrams
		 * and publish events upon reception.
		 * TODO: handle different clients 
		 */
		//initialize the transport protocol
		transport = new UDPTransport(port);
		//register this as subscriber to be updated on data reception
		transport.addIncomingDataListener(this);
		
		//initialize the list of subscribers
		subscribers = new ArrayList<DTLSConnector>();
		
		if (!isClient)
			LOG.info("Server waiting for a ClientHello");
	}

	public int getPort() {
		return port;
	}

	public InetAddress getAddress() {
		return address;
	}

	/**
	 * Sets the server address 
	 * 
	 * TODO: handle multiple servers
	 * 
	 * @param address
	 */
	public void setAddress(InetAddress address) {
		if (this.address == null)
			this.address = address;
	}

	public void setSendingPort(int sendingPort) {
		this.port = sendingPort;
	}

	/**
	 * The client calls this method to send DTLS encrypted data.
	 * If the handshake is not done, it is first performed and then
	 * send encrypted data.
	 * IF this method is called first (the state is INITIAL_STATE)
	 * then this is a DTLS client (trying to send data), so
	 * the state is PREPARING, in which the first handshake message
	 * is prepared
	 * @param data plaintext to be encrypted and sent
	 * @throws IOException 
	 */
	public void send(byte[] data) throws IOException{
		try{
			if (protocolState == ProtocolState.HANDSHAKE_COMPLETED){
				prepareAndSendAppData(data);
				System.exit(0);
			}else if (protocolState == ProtocolState.INITIAL_STATE){
				if ((data != null) && (data.length != 0)){
					dataBuffer.put(data);
					prepareNextFlight();
				}
			}else{
				//handshake in progress; data will be sent as soon
				//as it will be completed
				LOG.info("Applicatino data queued; handshake in progress");
				dataBuffer.put(data);
			}
		}catch (Exception e) {
			throw new IOException("Impossible to send data " + e);
		}
	}
	
	public int getSendingPort() {
		return port;
	}

	/**
	 * Method called by the server to receive encrypted data
	 * or wait for the ClientHello message
	 * @return
	 * @throws ProgramErrorException 
	 * @throws IOException 
	 */
	public byte[] receive() throws ProgramErrorException {
		if (isClient){
			//receiveDatagrams (STDTimeout)
			receiveDatagrams(Constants.RETRANSMISSION_TIME, true);
			
		}else {
		
			//check if the handshake must begin or it has already begun
			if (protocolState == ProtocolState.INITIAL_STATE)
				//in the first run of the server there is no
				//retransmission timer
				//waiting for the client hello
				receiveDatagrams(0, false);
				
			//now in both cases we wait for incoming data
			receiveDatagrams(Constants.RETRANSMISSION_TIME, true);
		}
		
		ByteBuffer b = ByteBuffer.allocate(1500 * receivedData.size());
		for (byte[] data : receivedData) {
			b.put(data);
		}
		
		//reset the buffer
		receivedData = new ArrayList<byte[]>();
		
		return Arrays.copyOfRange(b.array(), 0, b.position());

	}

	/**
	 * The waiting state is actually the reception of the datagrams
	 * unless the timer expires: in this case the last flight will be
	 * retransmitted.
	 * If a datagram is received, it is first parsed in Records (it might
	 * contain more than one record) then check if it is a retransmission
	 * or a new flight.
	 * After proper actions will be taken, and change the state to
	 * FINISHED or to PREPARING depending on the messages
	 * 
	 * Here we are in the WAITING state
	 * @param retransmission_time the time to wait before resending
	 * the last flight
	 * @throws ProgramErrorException 
	 * @throws IOException 
	 */
	private void receiveDatagrams(int retransmission_time, boolean stopRetransmissionTimer) throws ProgramErrorException {
		try{
			LOG.finest("WAITING STATE");
			
			List<DatagramPacket> datagrams = new ArrayList<DatagramPacket>();
			//temporary variable
			DatagramPacket datagram;
			
			/*
			 * if the retransmission time is zero,
			 * wait indefinitely till to the server
			 * receives the first datagram (the client hello) 
			 */
			if (retransmission_time == 0){
					
					//take the datagram from the queue
					datagram = datagramqueue.take();
					
					//only the first time take the address
					this.address = datagram.getAddress();
					//print the address
					LOG.fine("Client's address: " + datagram.getAddress().getHostAddress());
					
					parseAndDispatchReceivedDatagram(datagram);
					return;	//do not do anything else here
			}
			
			//here the retransmission time is != 0
			
			startOfWaitingState = System.currentTimeMillis();
			//retransmission timer working only during the handshake
			if ((protocolState != ProtocolState.HANDSHAKE_COMPLETED) &
				(stopRetransmissionTimer)){
				
				//cancel previous timer if any just to be sure
				stopRetransmissionTimer();
				//set a new timer
				retransmissionTimer = new Timer();
				//start the timer and stop it if it has been received something
				retransmissionTimer.schedule(new TimerTask() {
					
					@Override
					public void run() {
						try {
							LOG.info("Retransmission timer TimedOut; Resending Flight");
							sendFlight();
						} catch (IOException e) {
							LOG.severe("Exception in the timer: " + e.getMessage());
						} catch (ProgramErrorException e) {
							LOG.severe("Impossible to resend flight; exiting. " + e); 
						}
					}
				}, retransmission_time);
				LOG.info("Retransmission timer started with retransmission time: " + retransmission_time);
				
			}
			
			//read the received datagram(s)
			
			//take the first
			long timeToWait = retransmission_time - (startOfWaitingState - System.currentTimeMillis());
			LOG.fine("Waiting the next datagram for " + timeToWait/1000 + " seconds");
			datagram = datagramqueue.poll(timeToWait, TimeUnit.MILLISECONDS);
			
			//handle the received datagram
			parseAndDispatchReceivedDatagram(datagram);
			
	//		if (!isClient && retransmission_time == 0){
	//			datagram = datagramqueue.poll();
	//			System.out.println("Finally! Datagram taken from the queue");
	//			if (datagram != null){
	//				datagrams.add(datagram);
	//				LOG.finest("Datagram polled from the queue");
	//			}
	//			
	//			//retrieve client's address
	//			//TODO: extend to support more clients giving them an ID
	//			//that will be used also for session resuming
	//			this.address = datagram.getAddress();
	//			
	//			//print the address
	//			LOG.fine("Client's address: " + datagram.getAddress().getHostAddress());
	//		}else{
	//			try {
	//				//receive datagrams and waits till to it
	//				//will time out
	//				long now = System.currentTimeMillis();
	//				//wait the timer remaining to timeout
	//				datagram = datagramqueue.poll(retransmission_time - (now - timerStartingTime) , TimeUnit.MILLISECONDS);
	//				System.out.println("Finally! Datagram taken from the queue");
	//				if (datagram != null){
	//					datagrams.add(datagram);
	//					LOG.finest("Datagram polled from the queue");
	//				}
	//			} catch (InterruptedException e) {
	//				LOG.severe("Client datagram reception interrupted, " + e.getMessage());
	//			}
	//		}
			
			//dispatch the received datagrams
			for (DatagramPacket datagramPacket : datagrams) {
				parseAndDispatchReceivedDatagram(datagramPacket);
			}
		} catch (InterruptedException e) {
			throw new ProgramErrorException("Reception interrupted; impossible to receive datagrams: " + e.getMessage());
		}
	}

	/**
	 * This method parses a datagram (that may contain more than
	 * a single DTLS Record). Then checks if there are datagrams
	 * that must be read in the next epoch (that requires another
	 * state to be deciphered) putting them in queue.
	 * Finally dispatches the record to its own type (handshake, 
	 * application data, change cipher spec or alert)
	 * @param datagram
	 * @throws ProgramErrorException 
	 */
	private void parseAndDispatchReceivedDatagram(DatagramPacket datagram) throws ProgramErrorException {
		
		LOG.info("parseAndDispatchReceivedDatagram " + datagram);
		
		if (datagram == null){
			LOG.warning("Received null datagram");
			//go back to the receiving state within
			//the end of the timer
			
			//calculate how much time it is needed to be in the waiting state
			long timeElapsed = System.currentTimeMillis() - startOfWaitingState;
			LOG.fine("Waiting for more " + (Constants.RETRANSMISSION_TIME - timeElapsed)/1000d + " seconds" );
			
			if ((protocolState != ProtocolState.HANDSHAKE_COMPLETED))
					receiveDatagrams((int)(Constants.RETRANSMISSION_TIME - timeElapsed), false);
			return;
		}
		
		//parse received datagrams
		List<RecordLayer> received = new ArrayList<RecordLayer>();
		/*
		 * A datagram might contain more than a record layer
		 */
		List<RecordLayer> parsedDatagrams = parser.parseDatagram(datagram.getData()); 
		received.addAll(parsedDatagrams);
			
		//queuing records with epoch greater than the current
		nextEpochQueue.addAll(processEpoch(received));
		
		//if we received at least one record
		if (!received.isEmpty()){
			//dispatch the received flight
			LOG.info("Received flight: \n" + DTLSUtils.getDTLSRecordsString(received));
			
			//received flights are ordered based on sequence_number
			PriorityQueue<RecordLayer> queue = new PriorityQueue<RecordLayer>();
			queue.addAll(received);
			
			//processing queue
			processRecordQueue(queue);
		}
	}

	/**
	 * Exit from the program because of 
	 * a critical error
	 * @param alertLevel 
	 */
	private void exitWithError(int alertLevel) {
		System.exit(alertLevel);
	}

	/**
	 * This method processes a received queue of records.
	 * The queue must be a PriorityQueue, ordered by message_sequence (lower
	 * message sequence first).
	 * It is always populated with records of current epoch
	 * @param queue
	 * @throws ProgramErrorException 
	 * @throws IOException 
	 */
	private void processRecordQueue(PriorityQueue<RecordLayer> queue) throws ProgramErrorException{
		while (!queue.isEmpty()) {
			RecordLayer rec = (RecordLayer) queue.poll();
			
			try {
				//first decryption: the record fields are
				//deciphered and decompressed (not the fragment)
				rec.decryptAndDecompressFragment(this);
			} catch (DecryptionException e) {
				LOG.severe("Error during decryption: " + e.getMessage());
				prepareAlertAndExit(AlertLevel.fatal, AlertDescription.decryption_failed);
			}
			LOG.fine("Processing Record: \n" + DTLSUtils.getDTLSRecordString(rec));
			
			//now it is possible to choose the proper handling
			switch (rec.getContentType()) {
			
			//application data
			case ContentType.application_data:
				appDataQueue.add(rec);
				processApplicationData();
				break;
			
			//alert		//might not be needed a queue
			case ContentType.alert:
				alertQueue.add(rec);
				processAlert();
				break;
			
			//change cipger spec
			case ContentType.change_cipher_spec:
				processChangeCipherSpec();
				break;				
			
			//handshake messages
			case ContentType.handshake:
				handshakeQueue.add(rec);
				try {
					processHandshake();
				} catch (IOException e) {
					LOG.severe("Could not process handshake message");
					continue;
				}
				break;
			default:
				LOG.warning("Unespected behaviour; record discarded");
				break;
			}
		}
	}

	/**
	 * This method is called when the Change cipher spec is received
	 * @throws ProgramErrorException
	 */
	private void processChangeCipherSpec() throws ProgramErrorException {
		this.protocolState = ProtocolState.CHANGE_CIPHER_SPEC_RECEIVED;
		if (!isClient){
			//now it is possible to generate the master secret for the server
			generateMasterSecret();
		}
//		//prepare reading and writing cipher suites to be used
//		preparePendingCiphers();
		//now it is possible for the server to select cipher suites and compression 
		//method and put them in the pending state
		context.selectCipherAndCompression(this);	//calls DTLSAbstractContext
		
		//set the new reading cipher since we received a CCS
		this.readCipher = this.pendingReadCipher;
		LOG.fine("Switched from the current Reading state to the pending Reading state");

		increaseReadEpoch();
		
		//it is now possible to read next epoch queue if present
		processRecordQueue(nextEpochQueue);
	}
	
	/**
	 * Here are processed received records.
	 * @throws IOException
	 * @throws ProgramErrorException
	 */
	private synchronized void processHandshake() throws IOException, ProgramErrorException {
		
		while (!handshakeQueue.isEmpty()) {
			//take the first element 
			RecordLayer rec = handshakeQueue.poll();
			
			LOG.fine("Message sequence expected / received: [" + expectedMessageSequence +
					" / " + rec.getMessageSequence() + "]");
			
			//check for retransmissions
			//message sequence smaller than the expected one
			if (isRetransmission(rec)){
				LOG.warning("Discarding record " + DTLSUtils.getDTLSRecordString(rec));
				//if this is a retransmission return;
				//the timer won't be stopped and the 
				//protocol will retransmit the last flight
				return;
			}
			
			//if the message sequence is greater than the expected one
			//then this record must be processed later
			if (rec.getMessageSequence() > expectedMessageSequence){
				LOG.warning("Record not expected here, queuquing: " + DTLSUtils.getDTLSRecordString(rec));
				handshakeQueue.add(rec);
				return;
			}
			
			//here the record's message sequence is expected
			stopRetransmissionTimer();
			
			//set received record
			receivedRecords.add(rec);
			LOG.finest("Record added to the received records: " + DTLSUtils.getDTLSRecordString(rec));
			
			//update the checksum of the received flight
			updateHash(rec);
			
			//wait for the next record
			expectedMessageSequence++;
			LOG.fine("Increased expected message sequence. Now expected: " + expectedMessageSequence); 
			
			switch (((Fragment)rec.getFragment()).getMessage_type()) {
			
			case HandshakeType.client_hello:
				ClientHello clientHello = (ClientHello)((Fragment)rec.getFragment()).getBody();
				//received client hello
				//distinguish between first transmission and second transmission
				if (rec.getMessageSequence() == 0){
					changeProtocolStateTo(ProtocolState.FIRST_CLIENT_HELLO_RECEIVED);
					
					//store ClientHello data
					context.getSecurityParameters().setClientRandom(clientHello.getRandom());
					//TODO: handle sessionID (it might be a resumed handshake)
					
					//The cookie must be empty for the first ClientHello
									
					//store cipher suites and compression methods in the context
					context.setOfferedCipherSuites(clientHello.getCipher_suites());
					context.setOfferedCompressionMethods(clientHello.getCompression_methods());
					//store extensions offered
					context.setOfferedExtensions(clientHello.getExtensions());
					
				}else{
					changeProtocolStateTo(ProtocolState.SECOND_CLIENT_HELLO_RECEIVED);
					
					//if this is the second ClientHello, 
					//verify that the cookie is valid
					if (!
						(clientHello.getCookie_length() > 0) &
						Arrays.equals(generateCookie(), clientHello.getCookie())){
						//treat the message as it was a ClientHello without cookie
						LOG.severe("Cookie not valid; message discarded");
						rec = null;
						//interrupt and retransmit the HelloVerifyRequest
						sendFlight();
						return;
					}else{
						LOG.warning("Cookie not present or not valid; Cookie: " + clientHello.getCookie());
					}
					
				}
				
				prepareNextFlight();
				break;
				
			case HandshakeType.hello_verify_request:
				changeProtocolStateTo(ProtocolState.HELLO_VERIFY_REQUEST_RECEIVED);
				
				//the client received the first message from the server
				HelloVerifyRequest helloVerifyRequest = (HelloVerifyRequest)((Fragment)rec.getFragment()).getBody();
				this.context.setCookie(helloVerifyRequest.getCookie());
				
				//TODO: check the version received to see if it matches
				//for the moment it is assumed that both peers are DTLS 1.2
				
				prepareNextFlight();
				break;
				
			case HandshakeType.server_hello:
				changeProtocolStateTo(ProtocolState.SERVER_HELLO_RECEIVED);
				
				ServerHello serverHello = (ServerHello)((Fragment)rec.getFragment()).getBody(); 

				//store server random number in the context
				context.getSecurityParameters().setServerRandom(serverHello.getRandom());

				//store selected cipher suite
				context.setSelectedCipherSuite(serverHello.getCipher_suite());

				//store selected compression method
				context.setSelectedCompressionMethod(serverHello.getCompression_method());
				
				//now it is possible for the client to select cipher suites and compression 
				//method and put them in the pending state
				
				context.selectCipherAndCompression(this);				
				break;
				
			case HandshakeType.certificate:
				if (isClient){
					changeProtocolStateTo(ProtocolState.SERVER_CERTIFICATE_RECEIVED);
					LOG.finest("Validating Server certificate");
				}else{
					changeProtocolStateTo(ProtocolState.CLIENT_CERTIFICATE_RECEIVED);
					/**   
	   				 * The server validates the certificate chain, extracts the client's
					 * public key, and checks that the key type is appropriate for the
					 * client authentication method.
					 */
					LOG.finest("Validating Client certificate");
					
				}
				
				//certificate to verify
				Certificate cert = (Certificate)((Fragment)rec.getFragment()).getBody();
				
				if (CertificateVerifier.isValidAndVerified(cert, context)){
					LOG.fine("Certificate Valid");
					//store the certificate					
					((DTLSECCContext)context).setReceivedCertificates(cert.getCertificates());
				}else{
					//TODO: add reason
					LOG.severe("Certificate NOT Valid");
					prepareAlertAndExit(AlertLevel.fatal, AlertDescription.bad_certificate);
				}
				break;

			case HandshakeType.server_key_exchange:
				changeProtocolStateTo(ProtocolState.SERVER_KEY_EXCHANGE_RECEIVED);

				//selection of the key exchange method
				context.selectKeyExchangeMethod();
				
				//store information from the server
				//if ECDH verify the signature and set the pre-master secret
				ServerKeyExchange serverKeyExchange = (ServerKeyExchange)((Fragment)rec.getFragment()).getBody();
				
				//here verify the signature and calculation of the pms
				try {
					context.verifyServerKeyExchange(serverKeyExchange.getKeyExchange());
				} catch (SignatureNotValidException e) {
					prepareAlertAndExit(AlertLevel.fatal, AlertDescription.bad_certificate);
				}
				break;

			case HandshakeType.certificate_request:
				changeProtocolStateTo(ProtocolState.CERTIFICATE_REQUEST_RECEIVED);

				//the server wants to authenticate the client
				this.mutualAuth = true;

				break;

			case HandshakeType.server_hello_done:
				changeProtocolStateTo(ProtocolState.SERVER_HELLO_DONE_RECEIVED);
				
				//nothing to do here
				
				prepareNextFlight();
				break;

			case HandshakeType.client_key_exchange:
				changeProtocolStateTo(ProtocolState.CLIENT_KEY_EXCHANGE_RECEIVED);
				
				//if ecdh verify signature and set the pre-master secret
				//FIXME: select dynamically the server key exchange method; now ECDHE
				ClientKeyExchange clientKeyExchange = (ClientKeyExchange)((Fragment)rec.getFragment()).getBody(); 
				
				context.calculatePreMasterSecret(clientKeyExchange.getExchange_keys());				
				break;
				
			case HandshakeType.certificate_verify:
				changeProtocolStateTo(ProtocolState.CERTIFICATE_VERIFY_RECEIVED);

				CertificateVerify certificateVerify =  (CertificateVerify)((Fragment)rec.getFragment()).getBody();
				
				List<byte[]> data = new ArrayList<byte[]>();
				byte[] msgsHash = doFinal(sha1Hash);
				data.add(msgsHash);
				
				LOG.finest("Hash of the messages to verify the signing: " +
						DTLSUtils.getHexString(msgsHash));
				
				boolean signatureVerified;
				//hash already executed; now it is needed only to sign and verify the signature
				signatureVerified = DTLSSigner.verifySignature("NONEwithECDSA", ((DTLSECCContext)context).getReceivedCerts().get(0).getPublicKey(), 
						 data, certificateVerify.getSignatureOfMessagesHash());
				
				if (signatureVerified){
					LOG.fine("Signature in CertificateVerify Valid and verified");
				}else{
					LOG.severe("Client signature not valid in Certificate Verify, sending alert");
					prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
				}
				break;
				
			case HandshakeType.finished:
				changeProtocolStateTo(ProtocolState.FINISHED_RECEIVED);
				
				if (!isFinishedVerified(rec)){
					//finish doesn't match, send FATAL ALERT
					//and abort
					prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
				}else{
					finishFlights();
				}
				
				break;

			default:
				throw new ProgramErrorException("Error processing the handshake message;" +
						"Illegal state: HandshakeType not valid");
			}
		}//end of the loop		
	}

	/**
	 * Changes the current protocol state to the new state
	 * @throws ProgramErrorException 
	 */
	private void changeProtocolStateTo(int newProtocolState) throws ProgramErrorException {
		this.protocolState = newProtocolState;
		ProtocolState.logProtocolStateChange(newProtocolState);
	}

	/**
	 * Stops the retransmission timer and
	 */
	private void stopRetransmissionTimer() {
		//if there are datagrams received, do not retransmit
		if (retransmissionTimer != null){
			retransmissionTimer.cancel();
			LOG.fine("Retransmission timer canceled");
		}
	}

	/**
	 * This method prepares the next flight.
	 * It does the computations in order to prepare
	 * the next flight, that will be send in the
	 * sending state.
	 * 
	 * Here we are in the PREPARING state
	 * @throws IOException 
	 * @throws ProgramErrorException 
	 */
	private void prepareNextFlight() throws IOException, ProgramErrorException {
		
		LOG.finest("PREPARING STATE");
		
		//emptying sending buffer
		clearSendBuffer();
		
		switch (protocolState) {
		case ProtocolState.INITIAL_STATE:
			//client
			//*****CLIENT_HELLO (first transmission) *****
			preparedRecords.add(RecordLayer.getNewClientHello(context, null));
			LOG.fine("First ClientHello prepared");
			break;

		case ProtocolState.FIRST_CLIENT_HELLO_RECEIVED:
			//server
			//*****HELLO_VERIFY_REQUEST*****
			preparedRecords.add(RecordLayer.getNewHelloVerifyRequest(generateCookie()));
			LOG.fine("HelloVerifyRequest prepared");
			break;
			
		case ProtocolState.HELLO_VERIFY_REQUEST_RECEIVED:
			//client
			//*****CLIENT_HELLO (second transmission) *****
			
			//get cookie 
			byte[] cookie = context.getCookie();

			if (cookie != null){
				//set the cookie if not null
				RecordLayer newClientHello = RecordLayer.getNewClientHello(context, cookie);
				((ClientHello)((Fragment)newClientHello.getFragment()).getBody()).setCookie(cookie);
				((ClientHello)((Fragment)newClientHello.getFragment()).getBody()).setCookie_length((short) cookie.length);
				preparedRecords.add(newClientHello);
				LOG.fine("Second ClientHello prepared");
			}
			//otherwise cookie not existing
			//act as it was a client hello without cookie
			break;
			
		case ProtocolState.SECOND_CLIENT_HELLO_RECEIVED:
			//server
			//*****SERVER_HELLO*****
			RecordLayer serverHello;
			try {
				serverHello = RecordLayer.getNewServerHello(context);
				//cipher suite and compression method has been chosen
				//it is now possible to get the cipher and the hash
				preparedRecords.add(serverHello);
				LOG.fine("ServerHello prepared");

			} catch (NoCSFoundException e) {
				LOG.severe("The server has no Cipher Suites matching the one offered by the client. Exiting");						
				prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
			} catch (NoCMFoundException e) {
				LOG.severe("The server has no Compression Methods matching the one offered by the client. Exiting");
				prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
			}
			
			if (mustSendCertificate){
				//*****CERTIFICATE*****
				RecordLayer certificate = RecordLayer.getNewCertificate(context, isClient);
				preparedRecords.add(certificate);
				LOG.fine("Certificate prepared");
			}
			
			if (mustSendServerKeyExchange){
				//*****SERVER_KEY_EXCHANGE*****
				/*
				 * Get from the context the server key exchange.
				 * If it is null, then it is not needed and shall not be sent
				 */
				RecordLayer serverKeyExchange = context.getServerKeyExchange();
				if (serverKeyExchange != null){
					preparedRecords.add(serverKeyExchange);
					LOG.fine("ServerKeyExchange prepared");
				}
			}

			//*****CERTIFICATE_REQUEST*****
			if (this.mutualAuth){
				RecordLayer certificateRequest = RecordLayer.getNewCertificateRequest(context);
				preparedRecords.add(certificateRequest);
				LOG.fine("CertificateRequest prepared");
			}
				
			//*****SERVER_HELLO_DONE*****
			RecordLayer serverHelloDone = RecordLayer.getNewServerHelloDone();
			preparedRecords.add(serverHelloDone);
			LOG.fine("ServerHelloDone prepared");
			break;
			
		case ProtocolState.SERVER_HELLO_DONE_RECEIVED:
			//client

			//*****CERTIFICATE*****
			/*
			 * This message is sent after it has been received the
			 * certificate request from the server if the client has 
			 * a suitable certificate. In CertificateRequest
			 * the server specifies the type of certificate supported. 
			 */				
			if (mutualAuth){
				RecordLayer certificate = RecordLayer.getNewCertificate(context, isClient);
				preparedRecords.add(certificate);
				LOG.fine("Certificate prepared");
			}
			/*
			 * Now it is possible to select the next messages based on the cipher
			 * just selected. This will be done before the server key exchange
			 * is needed to be prepared. It can be also done just after the 
			 * reception of the server hello message
			 */
			if (clientKeyExchangeNeeded){
				//*****CLIENT_KEY_EXCHANGE*****
				RecordLayer clientKeyExchange = context.getClientKeyExchange();
				preparedRecords.add(clientKeyExchange);
				LOG.fine("ClientKeyExchange prepared");
			}
			//now it is possible to generate the master secret for the client
			generateMasterSecret();
			
			//now it is possible for the server to select cipher suites and compression 
			//method and put them in the pending state
			context.selectCipherAndCompression(this);
			
			//the write cipher will be changed once the CCS message is sent
			
			if (mutualAuth && clientCanSign){
				//*****CERTIFICATE_VERIFY*****
				//Create the message and complete it later
				RecordLayer certificateVerify = RecordLayer.getNewCertificateVerify();
				preparedRecords.add(certificateVerify);
				LOG.fine("CertificateVerify prepared");
			}

			//*****CHANGE_CIPHER_SPEC*****
			RecordLayer changeCipherspecClient = RecordLayer.getNewChangeCipherSpec();
			preparedRecords.add(changeCipherspecClient);
			LOG.fine("ChangeCipgerSpec prepared");
			
			//*****FINISHED*****
			RecordLayer finishedClient = RecordLayer.getNewFinished(context, null);
			preparedRecords.add(finishedClient);
			LOG.fine("Finished prepared");
			//verify_data updated later
 			break;
 			
		case ProtocolState.FINISHED_RECEIVED:
			//server

			//the server receives the finished message
			//then the ChangeCipherSpec and Finished must be sent

			//*****CHANGE_CIPHER_SPEC*****
			RecordLayer changeCipherspecServer = RecordLayer.getNewChangeCipherSpec();
			preparedRecords.add(changeCipherspecServer);
			LOG.fine("ChangeCipgerSpec prepared");
			
			//*****FINISHED*****
			RecordLayer finishedServer = RecordLayer.getNewFinished(context, null);
			preparedRecords.add(finishedServer);
			LOG.fine("Finished prepared");
			//verify_data updated later
			break;
			
		default:
			//TODO: might be just a warning in the log
			LOG.severe("PROTOCOL STATE NOT VALID");
			//alert sent for debug purpose
			prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
			break;
		}
		
		//THIS MUST BE DONE AT THE END OF THE METHOD
		
		//setting current epoch and messageSequence
		for (RecordLayer rec : preparedRecords){
			//if there is a ChangeCipherSpec, increase the epoch
			//by one 
			if (rec.getContentType() == ContentType.change_cipher_spec){
				//set current epoch +1 to the prepared records
				rec.setEpoch(currentWriteEpoch);
				increaseWriteEpoch();

			}else{
				//set current epoch to the prepared records
				rec.setEpoch(currentWriteEpoch);
				
				//set the message_sequence
				((Fragment)rec.getFragment()).setMessage_sequence(writingMessageSequence++);

				
				//for CertificateVerify
				/*
				 * The signature must be done here because we need the hashes of the
				 * messages we prepared; here is possible to compute the final
				 * hash and sign it then populate the certificate verify message
				 */
				if (isHansahakeType(rec, HandshakeType.certificate_verify)){
					CertificateVerify cv = (CertificateVerify) ((Fragment)rec.getFragment()).getBody();
					byte[] signature =
							//getting only ECDSA since we have already the SHA1 hash
							DTLSSigner.sign("NONEwithECDSA", 
							(PrivateKey) context.getSigningKey(), 
							doFinal(sha1Hash));

					//if the signing was not possible, send alert
					if (signature == null){
						prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
					}
					
					//postponing signature
					cv.setSignatureOfMessagesHash(signature);
						
					//update fragment length
					((Fragment)rec.getFragment()).setFragment_length(cv.getTotalByteLength());
					((Fragment)rec.getFragment()).setLength(cv.getTotalByteLength());
				}

				//update the state with the record that 
				//is going to be sent
				updateProtocolState(rec);	//must be done here after setting the message sequence

				//update hash
				updateHash(rec);
			}
		}

		//now that all the hashes are updated it is possible to calculate the
		//verify_data if the finished message is present
		RecordLayer rec = getRecordHandshakeType(preparedRecords, HandshakeType.finished);
		if (rec != null){
			Finished finished = (Finished)((Fragment)rec.getFragment()).getBody();

			byte[] verify_data = getVeritfyData(isClient);
			finished.setFinished(verify_data);
			//TODO: reduce coupling
			((Fragment)rec.getFragment()).setFragment_length(finished.getTotalByteLength());
			((Fragment)rec.getFragment()).setLength(finished.getTotalByteLength());
		}
		
//		LOG.finest("The following messages have been prepared for the next fligth: " +
//				DTLSUtils.getDTLSRecordsString(preparedRecords));
		
		//go to the sending state
		sendFlight();
	}

	private RecordLayer getRecordHandshakeType(List<RecordLayer> records, short type) {
		for (RecordLayer rec : records) {
			if (isRecordHandshakeType(rec, type)!= null)
				return rec;
		}
		return null;
	}

	/**
	 * The client verify data are different from the server verify data
	 * because the server includes the hash of the client finished, 
	 * the client doesn't
	 * @param isClient
	 * @return
	 */
	private byte[] getVeritfyData(boolean isClient) {
		//cloning current hash
		Digest tmpHash = new SHA256Digest((SHA256Digest)hash);
		if (isClient){
			byte[] finalHash = doFinal(tmpHash);

			LOG.finest("HASH without Finished: " + DTLSUtils.getHexString(finalHash));			
			byte[] prf = DTLSUtils.PRF(
					context.getSecurityParameters().getMasterSecret(),  Strings.toByteArray("client finished"),
	                finalHash, 12);
			LOG.finest("PRF Without Finished: "+ DTLSUtils.getHexString(finalHash));

			return prf;
		}else{
			//different variable (isClient) than the local one because this method
			//is calculated also on the client tocheck the verify_data
			if (!this.isClient)
				//the server needs to add the Client Finished message and compute again the hash
				addToHash(tmpHash, getRecordHandshakeType(receivedRecords, HandshakeType.finished));
			else
				addToHash(tmpHash, getRecordHandshakeType(transmittedRecords, HandshakeType.finished));

			byte[] finalHash = doFinal(tmpHash);
			LOG.finest("HASH with Finished: " + DTLSUtils.getHexString(finalHash));
			
			byte[] prf = DTLSUtils.PRF(
					context.getSecurityParameters().getMasterSecret(), Strings.toByteArray("server finished"),
	                finalHash, 12);

			LOG.finest("PRF With Finished: "+ DTLSUtils.getHexString(finalHash));

			return prf;
		}
	}
	
    private byte[] doFinal(Digest tmpHash){
	        byte[] finalHash = new byte[tmpHash.getDigestSize()];
	        tmpHash.doFinal(finalHash, 0);
		    return finalHash;
    }

	/**
	 * This method obtains the master secret from the 
	 * pre master secret, the client random and the server random
	 */
	private void generateMasterSecret() {
		byte[] pms = context.getPreMasterSecret();
		LOG.finest("PreMasterSecret " + DTLSUtils.getHexString(pms));
		
		LOG.finest("Client Random " + 
		DTLSUtils.getHexString(context.getSecurityParameters().getClientRandom()));


		LOG.finest("Server Random " + 
		DTLSUtils.getHexString(context.getSecurityParameters().getServerRandom()));
		
		byte[] seed = DTLSUtils.concat(context.getSecurityParameters().getClientRandom(),
		context.getSecurityParameters().getServerRandom());

		LOG.finest("Seed " + DTLSUtils.getHexString(seed));
		
		context.getSecurityParameters().setMasterSecret(
				DTLSUtils.PRF(pms, Strings.toByteArray("master secret"), seed, 48));
		
		LOG.fine("Master secret " + 
		DTLSUtils.getHexString(context.getSecurityParameters().getMasterSecret()));

	}

	public boolean isMutualAuth() {
		return mutualAuth;
	}

	public void setMutualAuth(boolean mutualAuth) {
		this.mutualAuth = mutualAuth;
	}

	/**
	 * This method creates a cookie to be sent with the
	 * HelloVerifyRequest.
	 * 
	 * see RFC 6347 page 17
	 * 
	 * @return
	 */
	private byte[] generateCookie() {
		/*
		 * simple generation of the cookie:
		 * concatenation of client address 
		 * and client random
		 */
		
		//address in bytes
		byte[] address = this.address.getAddress();
		
//		int cookie_length = address.length + context.getReceivedRandom().length;
		int cookie_length = 32;	//compatible with DTLS 1.0
		
		byte[] cookie = new byte[cookie_length];
	
		Digest digest = new SHA256Digest();
	
		digest.update(address, 0, address.length);
		digest.update(context.getSecurityParameters().getClientRandom(), 0, context.getSecurityParameters().getClientRandom().length);
		
		digest.doFinal(cookie, 0);
		
		return cookie;
	}

	/**
	 * 
	 */
	private void clearSendBuffer() {
		//clear the prepared flights
		preparedRecords.clear();
		LOG.fine("Sending buffer cleared");
	}

//	/**
//	 * This method updates the checksum of the received messages
//	 * in order to verify attacks during the handshake and confirm
//	 * the integrity of all the messages.
//	 * The first C 
//	 * @param received
//	 */
//	private void updateHash(List<RecordLayer> received) {
//		for (RecordLayer rec : received) {
//			updateHash(rec);;
//		}
//	}
	
	/**
	 * This method prepares an Alert messages based on level and description, 
	 * and it calls the method to send the alert
	 * @param alertLevel
	 * @param alertDescription
	 * @throws ProgramErrorException 
	 * @throws IOException
	 */
	private void prepareAlertAndExit(short alertLevel, short alertDescription) throws ProgramErrorException {
		//stop the retransmission timer
		stopRetransmissionTimer();
		
		RecordLayer alert = RecordLayer.getNewAlert(alertLevel, alertDescription, this);
		LOG.warning("Sending Alert !!!");
		//Send the alert
		preparedRecords.clear();
		preparedRecords.add(alert);
		try {
			sendFlight();
		} catch (IOException e) {
			LOG.severe("Impossible to send ALERT");
			exitWithError(alertLevel);
		}
		exitWithError(alertLevel);
	}

	/**
	 * Checks the checksum of the finished message.
	 * If it is valid, return true, otherwise return false
	 * @param received
	 * @return
	 */
	private boolean isFinishedVerified(RecordLayer rec) {
		//the verification is different from client and server
		
		//calculate own verify_data
		byte[] verify_data = getVeritfyData(!isClient);
		
		//check the verify_data
		Finished f = ((Finished)((Fragment)rec.getFragment()).getBody());
		LOG.finest("Received Verify_Data: " +
				DTLSUtils.getHexString(f.getFinished()));

		if (!org.spongycastle.util.Arrays.constantTimeAreEqual(verify_data, f.getFinished())){
			LOG.severe("Verify data do NOT match");
			LOG.severe("Local (expected) Verify data:" +
					DTLSUtils.getHexString(verify_data));
			LOG.severe("Received Verify_Data: " +
					DTLSUtils.getHexString(f.getFinished()));
			return false;
		}else{
			LOG.fine("Verify_data match, Correct");
			return true;
		}
		
	}

	/**
	 * This method prepare and send application data
	 * @param data 
	 * @throws IOException 
	 * @throws ProgramErrorException 
	 */
	private void prepareAndSendAppData(byte[] data) throws IOException, ProgramErrorException {
		
		clearSendBuffer();

		RecordLayer dataRecord = RecordLayer.getNewAppDataRecord(data);
		preparedRecords.add(dataRecord);
		
		//set current epoch to the prepared records
		dataRecord.setEpoch(currentWriteEpoch);
		
		//send the prepared flight
		sendFlight();
	}
	
	/**
	 * This method returns the record if the type is the one specified in the
	 * parameters, null otherwise
	 * @param rec
	 * @param handshakeType
	 * @return
	 */
	private RecordLayer isRecordHandshakeType(RecordLayer rec, short handshakeType) {
		if (rec.getContentType() == ContentType.handshake)
			if (((Fragment)rec.getFragment()).getMessage_type() == handshakeType){
				return rec;
			}
		return null;
	}

	/**
	 * The record is a retransmission if the handshake has a
	 * message sequence lower then the expected.
	 * @param received the flight to analyze
	 * @return true if there is a record that is a retransmission, false
	 * otherwise
	 * @throws ProgramErrorException 
	 */
	private boolean isRetransmission(RecordLayer rec) throws ProgramErrorException {
		return rec.getMessageSequence() < expectedMessageSequence;
	}

	/**
	 * This method processes application data received with the flight
	 * @param applicationData 
	 */
	private void processApplicationData() {
		//if the handshake is completed return the data
		if (protocolState == ProtocolState.HANDSHAKE_COMPLETED){
			
			while (!appDataQueue.isEmpty()) {
				/*
				 * process only if it is in the same epoch, otherwise leave in queue
				 * because it is possible to decrypt only records of the same epoch
				 */
				RecordLayer appData = appDataQueue.poll();
				publishPropertyEvent(((ApplicationData)appData.getFragment()).getApplication_data());
//				receivedData.add(((ApplicationData)appData.getFragment()).getApplication_data());
			}
//			//TODO: in this way we overwrite app data.
//			//Create a queue to queue app data instead, in case more
//			//than a app data record is carried in the same datagram
//			receivedData = new byte[applicationData.getTotalByteLength()];
//			
//			receivedData = ((ApplicationData)applicationData.getFragment()).getApplication_data();
			
		}else {
			/*
			 * RFC 6347 page 24
			 */
			//discarding
		}
		
	}

	/**
	 * Process alert Records
	 * @param alertQueue
	 */
	private void processAlert() {
		while (!alertQueue.isEmpty()) {
			RecordLayer rec = alertQueue.poll();
			processAlert(rec);
		}
	}
	
	/**
	 * Process a received Alert Record
	 * @param alert
	 */
	private void processAlert(RecordLayer alert) {
		System.exit(((Alert)alert.getFragment()).getAlertLevel());
	}

//	/**
//	 * Returns a list with only the record specified in the recordType field.
//	 * @param recordType content type to return
//	 * @param received
//	 * @return
//	 */
//	private List<RecordLayer> getRecords(short recordType, List<RecordLayer> received) {
//		ArrayList<RecordLayer> records = new ArrayList<RecordLayer>();
//		if (received != null){
//			for (RecordLayer recordLayer : received) 
//				if (isHansahakeType(recordLayer, recordType))
//					records.add(recordLayer);
//		}
//			
//		return records;
//	}

	/**
	 * This method discards the records that have a lower epoch
	 * than the current one and queue the records with epoch
	 * greater than the current one to be processed later.
	 * Records with greater epoch than the current are put in
	 * another queue and processed after the current epoch
	 * queue is processed.
	 * 
	 * NOTE: In case of ChangeCipherSpec the next record has an epoch
	 * increased by 1.
	 * @param received received flight
	 * @return 
	 */
	private List<RecordLayer> processEpoch(List<RecordLayer> received) {
		/*
		 * RFC 6347 page 9
		 */
		List<RecordLayer> toBeRemoved = new ArrayList<RecordLayer>();
		for (RecordLayer rec : received){
			LOG.fine("Epoch expected / received: [" + currentReadEpoch +
					" / " + rec.getEpoch() + "]");
			//if the epoch is less than the current epoch -1 
			if (rec.getEpoch() < currentReadEpoch){
				LOG.warning("Record with epoch < expected; silent discarding." + DTLSUtils.getDTLSRecordString(rec));
				toBeRemoved.add(rec);
			}else if (rec.getEpoch() > currentReadEpoch){
				LOG.fine("Record with epoch > expected; queuing. " + rec.getEpoch() + " : " + DTLSUtils.getDTLSRecordString(rec));
				//add to queue
				nextEpochQueue.add(rec);
				toBeRemoved.add(rec);
			}
		}
		//to avoid ConcurrentModificationException
		//now discard the detected records
		received.removeAll(toBeRemoved);
		return toBeRemoved;
	}

	/**
	 * This method parses and transmits the buffered messages.
	 * 
	 * the parsing must be done here because the sequence number
	 * must be incremented here because it must be incremented for
	 * each send and resend, hence it cannot be done in the PREPARING state
	 * 
	 * Here we are in the SENDING state
	 * @throws IOException 
	 * @throws ProgramErrorException 
	 */
	private void sendFlight() throws IOException, ProgramErrorException {
		LOG.finest("SENDING STATE");
//		LOG.finest("Sending the following flight: " +
//				DTLSUtils.getDTLSRecordsString(preparedRecords));
		
		//this buffer is used to send handshake messages
		ByteBuffer sendBuffer = ByteBuffer.allocate(Constants.SEND_BUFFER_SIZE);
		if (this.retransmissionTimer != null)
			this.retransmissionTimer.cancel();
		
		//always increase the sequence number here
		//because it can be a transmission or a retransmission
		for (RecordLayer rec : preparedRecords){
			rec.setSequence_number(this.writingSequenceNumber++);

			//if we are not retransmitting the
			//last flight, add it to the 
			//transmitted records
			if (!receivedRetransmission(rec))
				transmittedRecords.add(rec);
			
			//MOVED TO PREPARING STATE
//			//update the state with the record that 
//			//is going to be sent
//			updateProtocolState(rec);

			//encode and encrypt records 
			//with the current cipher
 			try {
				rec.compressAndEncryptRecord(this);
			} catch (EncryptionException e) {
				prepareAlertAndExit(AlertLevel.fatal, AlertDescription.handshake_failure);
			}
						
			//recalculate the length of the encrypted record
			rec.updateLength();
			
//			//adding parsed record to the send buffer
			sendBuffer.put(parser.parseRecord(rec));
			
			if (this.sendSeparately){
				//if each record must be sent in a separate datagram
				sendBufferedRecords(sendBuffer);	
				
				sendBuffer = ByteBuffer.allocate(Constants.SEND_BUFFER_SIZE);
			}
			
			//after the CCS we use the previously negotiated parameters
			if (rec.getContentType() == ContentType.change_cipher_spec){
				writeCipher = pendingWriteCipher;
				LOG.fine("Switched from the current Writing state to the pending Writing state");
//				increaseWriteEpoch();
			}
		}

		if (!this.sendSeparately){
			//send the buffered message
			sendBufferedRecords(sendBuffer);
		}
		
		RecordLayer lastTransmitted = transmittedRecords.get(transmittedRecords.size()-1);

		//if it has been sent an alert, terminate with error
		if (lastTransmitted.getContentType() == ContentType.alert){
			processAlert(lastTransmitted);
			return;
		}
		
		//if the handshake is finished, we sent application data. nothing to receive now
		if (protocolState != ProtocolState.HANDSHAKE_COMPLETED){
			
			//if the last message was finished go to the finished state
			if (isHansahakeType(lastTransmitted, HandshakeType.finished))
				//go to the finshed state
				finishFlights();
			else
				//go to the waiting state
				receiveDatagrams(Constants.RETRANSMISSION_TIME, true);
		}
	}

	/**
	 * This method increases the epoch.
	 * When this happens, the message sequence
	 * start again from zero so the
	 * writing message sequence is reset to 0
	 */
	private void increaseWriteEpoch() {
		currentWriteEpoch++;
		LOG.finest("Epoch (Write) Increased");
		writingSequenceNumber = 0;
		LOG.finest("Writing sequence number reset to 0");
	}
	
	/**
	 * This method increases the read epoch when 
	 * a change cipger spec message is received.
	 * The expected sequence number is
	 * also reset to 0
	 */
	private void increaseReadEpoch() {
		//increase reading epoch
		currentReadEpoch++;
		LOG.finest("Epoch (Read) Increased");
		//resetting the sequence number
		expectedSequenceNumber = 0;
		LOG.finest("Expected sequence number reset to 0");
	}
	
	/**
	 * This method sets the protocol state based on the message sent
	 * for handshake messages
	 * @param rec
	 * @throws ProgramErrorException 
	 */
	private void updateProtocolState(RecordLayer rec) throws ProgramErrorException {
		if (rec.getContentType() == ContentType.handshake){
			Fragment fragment = (Fragment)rec.getFragment();
			
			switch (fragment.getMessage_type()) {
			
			case HandshakeType.client_hello:
				if (fragment.getMessage_sequence() == 0){
					this.protocolState = ProtocolState.FIRST_CLIENT_HELLO_SENT;
				}else{
					this.protocolState = ProtocolState.SECOND_CLIENT_HELLO_SENT;
				}
				break;
	
			case HandshakeType.hello_verify_request:
				this.protocolState = ProtocolState.HELLO_VERIFY_REQUEST_SENT;
				break;
			
			case HandshakeType.server_hello:
				this.protocolState = ProtocolState.SERVER_HELLO_SENT;
				break;
				
			case HandshakeType.certificate:
				if (isClient){
					this.protocolState = ProtocolState.CLIENT_CERTIFICATE_SENT;
				}else{
					this.protocolState = ProtocolState.SERVER_CERTIFICATE_SENT;
				}
				break;
				
			case HandshakeType.server_key_exchange:
				this.protocolState = ProtocolState.SERVER_KEY_EXCHANGE_SENT;
				break;
				
			case HandshakeType.certificate_request:
				this.protocolState = ProtocolState.CERTIFICATE_REQUEST_SENT;
				break;
				
			case HandshakeType.server_hello_done:
				this.protocolState = ProtocolState.SERVER_HELLO_DONE_SENT;
				break;
				
			case HandshakeType.client_key_exchange:
				this.protocolState = ProtocolState.CLIENT_KEY_EXCHANGE_SENT;
				break;
				
			case HandshakeType.certificate_verify:
				this.protocolState = ProtocolState.CERTIFICATE_VERIFY_SENT;
				break;
				
			case HandshakeType.finished:
				this.protocolState = ProtocolState.FINISHED_SENT;
				break;
			}
			ProtocolState.logProtocolStateChange(protocolState);
		}
	}

	/**
	 * This methods calculates the hash of the current record
	 * (that is one of the records that is about to be sent
	 * or a received record) before is encrypted and compressed
	 * when sending, and after it is decrypted and decompressed
	 * when receiving.
	 * The first ClientHello, HelloVerifyRequest and Finished 
	 * should not be included (and neither ChangeCipherSpec)
	 * @param rec
	 */
	private void updateHash(RecordLayer rec) {
		//if the hash has been completed, don't update it again
		if (rec.getContentType() == ContentType.handshake){
			
			//TODO: remove fragmentation or the hash will not match
			
			if (!(isHansahakeType(rec, HandshakeType.hello_verify_request) ||
					(isHansahakeType(rec, HandshakeType.finished)))){
				//if it is not helloVerifyRequest or Finished

				if (isHansahakeType(rec, HandshakeType.client_hello)){
					//if it is the second client hello, update the hash
					//the second client hello has message sequence != 0
					if (((Fragment)rec.getFragment()).getMessage_sequence() != 0){
						
						//for verify_data in the Finished message
						addToHash(this.hash, rec);
						
						//for CertificateVerify
						if (!(isHansahakeType(rec, HandshakeType.certificate_verify))) 
							//maintain also a sha1 digest of the messages
							addToHash(this.sha1Hash, rec);
					}
				}else{
					//add all the other possible records
					
					//for verify_data in the Finished message
					addToHash(this.hash, rec);
					
					//for CertificateVerify
					if (!(isHansahakeType(rec, HandshakeType.certificate_verify)))
						//maintain also a sha1 digest of the messages
						addToHash(this.sha1Hash, rec);
				}
			}
		}
					
	}
	
	/**
	 * This method parses the record and then adds it 
	 * to the digest
	 * @param hash
	 * @param rec
	 */
	private void addToHash(Digest hash, RecordLayer rec) {
		if (rec.getContentType() == ContentType.handshake){
			byte[] toHash;
			toHash = parser.parseFragment((Fragment)rec.getFragment());
			LOG.fine("*** Updating " + hash.getAlgorithmName() + "  hash of: " + DTLSUtils.getDTLSRecordString(rec)
					+ "With these bytes: " + DTLSUtils.getHexString(toHash));
			//updating hash
			hash.update(toHash,0,toHash.length);
		}
	}

	/**
	 * This method sends the prepared records through the transport
	 * protocol
	 * @param sendBuffer
	 * @throws SocketException 
	 */
	private void sendBufferedRecords(ByteBuffer sendBuffer) {
		//if it is a client send on the normal port
		//if it is the server send on the normal port +1
		if (isClient)
			LOG.fine("DTLS Client sending to: " + this.address + ":" + port);
		else
			LOG.fine("DTLS Server sending to: " + this.address + ":" + port);
		
		LOG.fine(DTLSUtils.getDTLSRecordsString(preparedRecords));
		
		try {
			//TODO: check
			//extract only the real data
			byte[] data = Arrays.copyOfRange(sendBuffer.array(), 0, sendBuffer.position());
			//send buffered messages
			transport.send(this.address, this.port, data);
		} catch (SocketException e) {
			LOG.severe("Not possible send DTLS records: " + e.getMessage());
			exitWithError(-1);
		} catch (IOException e) {
			LOG.severe("Not possible send DTLS records: " + e.getMessage());
			exitWithError(-1);
		}
	}

	/**
	 * Checks if the current record is a retransmission.
	 * This is obtained thanks to the RecordLayer's
	 * hash() and equals() that ignore the sequence_number 
	 * (incremented every retransmission).
	 * 
	 * A record is a received retransmission if the record
	 * has been already received and it is present in the
	 * received records.
	 * 
	 * @param rec the record to check against the received records
	 * @return true if rec is present in the received records,
	 * false otherwise
	 */
	private boolean receivedRetransmission(RecordLayer rec) {
		return receivedRecords.contains(rec);
	}
	
	/**
	 * This method represents the finished state.
	 * In this process the last flight is retransmitted/received
	 * and the last calculations are done.
	 * The exit from this state will determine the end of the
	 * handshake and the possibility of send and receive
	 * encrypted data
	 * 
	 * We are in the FINISHED state
	 * @throws IOException 
	 * @throws ProgramErrorException 
	 */
	private void finishFlights() throws IOException, ProgramErrorException {
		clearSendBuffer();
		stopRetransmissionTimer();
		//action differ whether this is a client or a server
		if (isClient){
			//this state is reached for the first time as soon as the finished 
			//message is sent but still not received.
			if (protocolState == ProtocolState.FINISHED_RECEIVED){
				//end of the handshake for the client
				protocolState = ProtocolState.HANDSHAKE_COMPLETED;
				ProtocolState.logProtocolStateChange(protocolState);
				clearSendBuffer();
				LOG.info("\nClient handshake completed!\n");
				
				LOG.info("Flights sent: " + DTLSUtils.getDTLSRecordsString(transmittedRecords));
				
				LOG.info("Flights received: " + DTLSUtils.getDTLSRecordsString(receivedRecords));
				
				//checking for buffered data to send
				if (dataBuffer != null && dataBuffer.position() > 0){
					LOG.fine("Sending application data buffered before the handshake started");
					prepareAndSendAppData(Arrays.copyOfRange(dataBuffer.array(), 0, dataBuffer.position()));
				}

				/*
				 * From now on when application data is received,
				 * decipher them and publish the reception to
				 * the upper layers
				 */
				startContinuousDataReception();
				
			}else {
				//so here we wait for the server last messages
				receiveDatagrams(Constants.RETRANSMISSION_TIME, true);
			}
		}else{
			if (protocolState == ProtocolState.FINISHED_SENT){
				//end of the handshake for the server
				protocolState = ProtocolState.HANDSHAKE_COMPLETED;
				ProtocolState.logProtocolStateChange(protocolState);
				clearSendBuffer();
				LOG.info("\nServer handshake completed!\n");
				
				LOG.info("Flights sent: " + DTLSUtils.getDTLSRecordsString(transmittedRecords));
				
				LOG.info("Flights received: " + DTLSUtils.getDTLSRecordsString(receivedRecords));

				
				/*
				 * From now on when application data is received,
				 * decipher them and publish the reception to
				 * the upper layers
				 */
				startContinuousDataReception();
				
				//TODO: when sending finished the retransmission timer
////				//must be double
////				//wait for retransmission of the last flight for the client
////				//RFC 6347 p 23
////				receiveDatagrams(Constants.RETRANSMISSION_TIME * 2);
			}else{
				prepareNextFlight();
			}
		}
	}

//	/**
//	 * This method returns true if the final flight 
//	 * has been retransmitted, false otherwise.
//	 * This is done because the client must retransmit
//	 * the last flight when receiving the finished
//	 * message from the server
//	 * @return
//	 */
//	private boolean sentFinishedRetransmission() {
//		//copy of the transmitted records
//		List<RecordLayer> transmitted = new ArrayList<RecordLayer>();
//		transmitted.addAll(transmittedRecords);
//		
//		//get the finished message
//		RecordLayer finished = transmitted.get(transmitted.size()-1);
//		//remove the finished from the list (copy)
//		transmitted.remove(finished);
//		//if there is another one, it is a retransmission
//		if (transmitted.contains(finished)){
//			return true;
//		}
//		else{
//			return false;
//		}
//	}

	/**
	 * The handshake here is completed;
	 * now process every record immediately
	 * as it is received
	 * @throws ProgramErrorException 
	 */
	private void startContinuousDataReception() throws ProgramErrorException {
		processDirectly = true;
	}

	/**
	 * Checks if the record is an handshake with the type
	 * specified in recordType
	 * @param recor
	 * @param handshakeType
	 * @return
	 */
	private boolean isHansahakeType(RecordLayer record, int handshakeType) {
		
		if ((record.getContentType() == ContentType.handshake) &&
				(record.getFragment() != null)){
			
			Fragment fragment = (Fragment)record.getFragment();
			
			if (fragment.getMessage_type() == handshakeType)
				return true;
			else
				return false;
			
		}else
			return false;
	}

	/**
	 * Returns the current cipher suite used to decrypt the records
	 * @return
	 */
	public DTLSCipher getReadCipher() {
		return readCipher;
	}

	/**
	 * Returns the current compression method to decompress
	 * the records
	 * @return
	 */
	public DTLSCompression getReadCompression() {
		return readCompression;
	}

	/**
	 * Returns the current cipher suite used to
	 * encrypt the records
	 * @return
	 */
	public DTLSCipher getWriteCipher() {
		return writeCipher;
	}

	/**
	 * Returns the current compression method used to decompress
	 * the records
	 * @return
	 */
	public DTLSCompression getWriteCompression() {
		return writeCompression;
	}

	public DTLSCipher getPendingReadCipher() {
		return pendingReadCipher;
	}

	public void setPendingReadCipher(DTLSCipher pendingReadCipher) {
		this.pendingReadCipher = pendingReadCipher;
	}

	public DTLSCipher getPendingWriteCipher() {
		return pendingWriteCipher;
	}

	public void setPendingWriteCipher(DTLSCipher pendingWriteCipher) {
		this.pendingWriteCipher = pendingWriteCipher;
	}

	public DTLSCompression getPendingReadCompression() {
		return pendingReadCompression;
	}

	public void setPendingReadCompression(DTLSCompression pendingReadCompression) {
		this.pendingReadCompression = pendingReadCompression;
	}

	public DTLSCompression getPendingWriteCompression() {
		return pendingWriteCompression;
	}

	public void setPendingWriteCompression(DTLSCompression pendingWriteCompression) {
		this.pendingWriteCompression = pendingWriteCompression;
	}

	public DTLSContext getContext() {
		return context;
	}

	public boolean isClient() {
		return isClient;
	}

	public DTLSParser getParser() {
		return parser;
	}

	/**
	 * Method called by the transport upon reception of a new
	 * datagram.
	 * @throws ProgramErrorException 
	 */
	@Override
	public void onPropertyEvent(Object sender, Object value) {
		if (value instanceof DatagramPacket){
			
			LOG.finest("Handler received a datagram from the transport");
			//add the datagram in the queue to be further analyzed
			datagramqueue.add((DatagramPacket) value);
			
			//the sever starts without response timer
			if (!isClient && protocolState == ProtocolState.INITIAL_STATE){
				LOG.fine("Server received first message");
				try {
					receiveDatagrams(0, false);
				} catch (ProgramErrorException e) {
					LOG.severe("Impossible to receive datagrams. " + e);
					exitWithError(-1);
				}
			}
			LOG.finest("Datagram added to the handler queue to be processed");
			
			//TODO: process the datagram directy here if the handshake is complete
			if (processDirectly){
				try {
					parseAndDispatchReceivedDatagram(datagramqueue.poll());
				} catch (ProgramErrorException e) {
					LOG.severe("Impossible to process the received datagram: " + e.getMessage());
					//the datagram will be ignored
				}
			}
			
		}
		//not interested in other events
	}

	/**
	 * Add a subscriber to listen for notification from
	 * this object
	 * @param connector
	 */
	public void registerSubscriber(DTLSConnector connector) {
		this.subscribers.add(connector);
	}
	
	/**
	 * Publishes the received data to all the subscribers
	 * @param value
	 */
	private void publishPropertyEvent(Object value){
		for (DTLSConnector connector : subscribers) {
			connector.DataReceived(this, value);
		}
	}

}
