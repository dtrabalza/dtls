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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x509.X509CertificateStructure;
import org.spongycastle.crypto.dtls.constants.ContentType;
import org.spongycastle.crypto.dtls.constants.HandshakeType;
import org.spongycastle.crypto.dtls.core.handshake.Certificate;
import org.spongycastle.crypto.dtls.core.handshake.CertificateRequest;
import org.spongycastle.crypto.dtls.core.handshake.CertificateVerify;
import org.spongycastle.crypto.dtls.core.handshake.ChangeCipherSpec;
import org.spongycastle.crypto.dtls.core.handshake.ClientHello;
import org.spongycastle.crypto.dtls.core.handshake.ClientKeyExchange;
import org.spongycastle.crypto.dtls.core.handshake.DistinguishedName;
import org.spongycastle.crypto.dtls.core.handshake.ECPointFormatList;
import org.spongycastle.crypto.dtls.core.handshake.Elliptic_Curve;
import org.spongycastle.crypto.dtls.core.handshake.Extension;
import org.spongycastle.crypto.dtls.core.handshake.Finished;
import org.spongycastle.crypto.dtls.core.handshake.HelloVerifyRequest;
import org.spongycastle.crypto.dtls.core.handshake.ServerHello;
import org.spongycastle.crypto.dtls.core.handshake.ServerKeyExchange;
import org.spongycastle.crypto.dtls.core.handshake.SignatureAndHashAlgorithm;
import org.spongycastle.crypto.dtls.core.keyExchange.ECParameters;
import org.spongycastle.crypto.dtls.core.keyExchange.EC_DIFFIE_HELLMAN;
import org.spongycastle.crypto.dtls.core.keyExchange.ServerECDHParams;
import org.spongycastle.crypto.dtls.exceptions.ProgramErrorException;
import org.spongycastle.crypto.dtls.interfaces.FragmentType;
import org.spongycastle.crypto.dtls.interfaces.HandshakeMessage;
import org.spongycastle.crypto.dtls.utils.DTLSUtils;
import org.spongycastle.crypto.tls.ExtensionType;

/**
 * This class implements the common operations for other parser
 *
 * @author Daniele Trabalza <daniele@sics.se>
 */
public class DTLSParser {

	/**
	 * Parses one of the handshake messages 
	 * in an array of bytes.
	 * @param messageType the type of handshake message
	 * @param body the handshake message to parse
	 * @return
	 */
	private byte[] parseHandshake(short messageType, HandshakeMessage body) {
		ByteBuffer buf = ByteBuffer.allocate(body.getTotalByteLength());
		
		switch (messageType) {

		case HandshakeType.hello_request:
			// TODO to complete
			return null;
			
		case HandshakeType.client_hello:
			ClientHello clientHello = (ClientHello)body;
			// 2 bytes client_version
			buf.put((byte) ~new Short(clientHello.getClient_version().getMajor()).byteValue());
			buf.put((byte) ~new Short(clientHello.getClient_version().getMinor()).byteValue());

			// 32 bytes random
			buf.put(clientHello.getRandom());

			// 1 byte session_id_lenght
			buf.put(new Short(clientHello.getSession_id_length()).byteValue());

			// if present, session_id_length bytes of session_id
			if (clientHello.getSession_id_length() > 0) {
				buf.put(clientHello.getSession_id());
			}

			// 1 byte cookie_length
			buf.put(new Short(clientHello.getCookie_length()).byteValue());

			// if present, cookie_length bytes of cookie
			if (clientHello.getCookie_length() > 0) {
				buf.put(clientHello.getCookie());
			}

			// 2 bytes cypher_suites_length
			buf.put(DTLSUtils.getBytesFromValue(clientHello.getCipher_suites_length(), 2));

			// if present, cypher_suites_length bytes of cypher_suites
			if (clientHello.getCipher_suites_length() > 0) {
				//2 bytes each but read one by one since 2 bytes are represented by an integer
				for (int i=0; i< clientHello.getCipher_suites().length; i++){
					buf.put(DTLSUtils.getBytesFromValue(clientHello.getCipher_suites()[i], 2));
				}
			}

			// 1 byte compression_methods_length
			buf.put(new Short(clientHello.getCompression_methods_length()).byteValue());

			// if present, compression_methods_length bytes of
			// compression_methods
			if (clientHello.getCompression_methods_length() > 0) {
				//1 byte each
				for (int i=0; i<clientHello.getCompression_methods_length(); i++){
					buf.put(new Short(clientHello.getCompression_methods()[i]).byteValue());
				}
			}
			
			//parsing extensions
			if (clientHello.getExtensions_length() != 0 && (!clientHello.getExtensions().isEmpty())){
				//there are extensions; parse them
				
				//2 bytes extensions length
				buf.put(DTLSUtils.getBytesFromValue(clientHello.getExtensions_length(), 2));
				
				for (Extension ext : clientHello.getExtensions()) {
					buf.put(parseExtension(ext));
				}
			}
			
			break;
			
		case HandshakeType.hello_verify_request:
			HelloVerifyRequest helloVerifyRequest = (HelloVerifyRequest)body;
			
			// 2 bytes client_version
			buf.put((byte) ~new Short(helloVerifyRequest.getServer_version().getMajor()).byteValue());
			buf.put((byte) ~new Short(helloVerifyRequest.getServer_version().getMinor()).byteValue());

			// 1 byte cookie_length
			buf.put(new Short(helloVerifyRequest.getCookie_length()).byteValue());

			// if present, cookie_length bytes of cookie
			if (helloVerifyRequest.getCookie_length() > 0) {
				buf.put(helloVerifyRequest.getCookie());
			}
			break;
			
		case HandshakeType.server_hello:
			ServerHello serverHello = (ServerHello)body;
			
			// 2 bytes server_version
			buf.put((byte) ~new Short(serverHello.getServer_version().getMajor()).byteValue());
			buf.put((byte) ~new Short(serverHello.getServer_version().getMinor()).byteValue());
			
			// 32 bytes random
			buf.put(serverHello.getRandom());
			
			// 1 byte session_id_length
			buf.put(new Short(serverHello.getSession_id_length()).byteValue());
			
			// if present, session_id_length bytes of session_id
			if (serverHello.getSession_id_length() > 0) {
				buf.put(serverHello.getSession_id());
			}	
			
			//2 bytes cipher_suite
			buf.put(DTLSUtils.getBytesFromValue(serverHello.getCipher_suite(), 2));
			
			//1 byte compression_method
			buf.put(new Short(serverHello.getCompression_method()).byteValue());
			
			//parsing extensions
			if (serverHello.getExtensions_length() != 0 && (!serverHello.getExtensions().isEmpty())){
				//there are extensions; parse them
				
				//2 bytes extensions length
				buf.put(DTLSUtils.getBytesFromValue(serverHello.getExtensions_length(), 2));
				
				for (Extension ext : serverHello.getExtensions()) {
					buf.put(parseExtension(ext));
				}
			}			
			
			break;
			
		case HandshakeType.certificate:
			Certificate certificate = (Certificate)body;
		
			try {
			
				//3 bytes certificates_length
				buf.put(DTLSUtils.getBytesFromValue(certificate.getCertificates_length(), 3));
				
				byte[] encoded;
				for (X509Certificate cert : certificate.getCertificates()) {
					
					encoded = cert.getEncoded();
					//3 bytes certificate_length
					buf.put(DTLSUtils.getBytesFromValue(encoded.length, 3));
					
					//certificate_length bytes of certificate
					buf.put(encoded);
					
				}

			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			break;
		
		case HandshakeType.server_key_exchange:
			ServerKeyExchange serverKeyExchange = (ServerKeyExchange)body;
			
			if (serverKeyExchange.getKeyExchange() instanceof EC_DIFFIE_HELLMAN){
				EC_DIFFIE_HELLMAN ecdh = (EC_DIFFIE_HELLMAN) serverKeyExchange.getKeyExchange();
				
				//1 byte curve_type
				buf.put((byte)ecdh.getParams().getCurve_params().getCurve_type());
				
				//2 bytes named_curve
				buf.put(DTLSUtils.getBytesFromValue(
						ecdh.getParams().getCurve_params().getNamedCurve(), 2));
				
				//1 byte ECPoint_length
				buf.put(DTLSUtils.getBytesFromValue(ecdh.getParams().getEcPointLength(),1));
				
				//ECPoint
				buf.put(ecdh.getParams().getEcPoint());
				
				//2 bytes signature_length
				buf.put(DTLSUtils.getBytesFromValue(ecdh.getSignatureLength(),2));
				
				//Signature
				buf.put(ecdh.getSignature());
				
			}else{
				//not yet implemented
			}
			
			break;
			
		case HandshakeType.certificate_request:
			CertificateRequest certificateRequest = (CertificateRequest)body;
			
			//1 byte certificate_type_length
			short certificateTypesLength = certificateRequest.getClientCertificateTypes_length(); 
			buf.put((byte)certificateTypesLength);
			
			//1 byte each certificate_type
			for (int i = 0; i < certificateTypesLength; i++) {
				buf.put((byte)certificateRequest.getClientCertificateTypes()[i]);
			}
			
			//2 bytes supported_signature_algorithms_length
			buf.put(DTLSUtils.getBytesFromValue(certificateRequest.getSignatureAndHashAlgorithms_length(), 2));
			
			//for each signature and hash algorithm
			for (SignatureAndHashAlgorithm sa : certificateRequest.getSignatureAndHashAlgorithms()) {
				//1 byte hash algorithm
				buf.put((byte)sa.getHashAlgorithm());

				//1 byte signature algorithm
				buf.put((byte)sa.getSignature());
			}
			
			//2 bytes dn_total_length
			buf.put(DTLSUtils.getBytesFromValue(certificateRequest.getDistinguishedNames_length(), 2));
				
			//for each DN
			for (DistinguishedName dn : certificateRequest.getDistinguishedNames()) {
				
				//2 bytes length
				buf.put(DTLSUtils.getBytesFromValue(dn.getDn_length(), 2));
				
				//dn
				buf.put(dn.getDn());
			}

			break;
			
		case HandshakeType.server_hello_done:
			// the message server_hello_done doesn't contain any body
			return null;	//nothing to do here
			
		case HandshakeType.certificate_verify:
			CertificateVerify certificateVerify = (CertificateVerify)body;
			
			//1 byte hash algorithm
			buf.put((byte)certificateVerify.getSignatureAndHashAlgorithm().getHashAlgorithm());

			//1 byte signature algorithm
			buf.put((byte)certificateVerify.getSignatureAndHashAlgorithm().getSignature());
			
			//2 bytes length
			buf.put(DTLSUtils.getBytesFromValue(certificateVerify.getLength(), 2));
			
			//[length] bytes
			buf.put(certificateVerify.getSignatureOfMessagesHash());
			
			break;
			
		case HandshakeType.client_key_exchange:
			ClientKeyExchange clientKeyExchange = (ClientKeyExchange)body;
			
			//if the length is 0 don't put any field
			if (clientKeyExchange.getLength() != 0){
			
				//1 byte length
				buf.put(DTLSUtils.getBytesFromValue(clientKeyExchange.getLength(), 1));
	
				//remaining bytes
				if (clientKeyExchange.getLength() != 0)
					buf.put(clientKeyExchange.getExchange_keys());
			}

			break;
			
		case HandshakeType.finished:
			Finished finished = (Finished)body;
			if (finished.getFinished() != null)
				buf.put(finished.getFinished());
			break;

		default:
			
			break;
		}
		
		return Arrays.copyOfRange(buf.array(), 0, buf.position());
	}
	
	/**
	 * This method parses an extension from the object to byte array
	 * and returns the byte array
	 * @param ext
	 * @return
	 */
	private byte[] parseExtension(Extension ext){
		ByteBuffer buf = null;
		
		//allocate buffer
		buf = ByteBuffer.allocate(ext.getTotalByteLength());
		
		//2 bytes type
		buf.put(DTLSUtils.getBytesFromValue(ext.getType(), 2));
		
		//2 bytes data_length
		buf.put(DTLSUtils.getBytesFromValue(ext.getExtensionLength(), 2));

		//variable depending on ext.getData().getTotalByteValue()
		buf.put(ext.getData().getBytes());

		return buf.array();
	}
	
	/**
	 * This method parses and return a handshake message
	 * 
	 * @param message_type used to determine how to parse bytes. It is 
	 * contained in the fragment.
	 * @param i 
	 * @param body the byte array to parse containing one of the 
	 * handshake messages. See the interface crypto.dtls.interfaces.HandshakeMessage
	 * @return
	 */
	private HandshakeMessage parseHandshake(short message_type, int totalBodyLength, byte[] body) {
		
		ByteBuffer dGramsQueuque = ByteBuffer.wrap(body);
		
		//a temporary array to read from the buffer
		byte[] tmpArr;
//		// current read position of the array
//		int relativeIndex = 0;
		
		// according to the message type the handshake messages is parsed in a
		// different way
		switch (message_type) {

		case HandshakeType.hello_request:
			// TODO to complete
			return null;
			
		case HandshakeType.client_hello:
			ClientHello clientHello = new ClientHello();

			// 2 bytes client_version
			clientHello.setClient_version(new Version((byte) ~new Byte(dGramsQueuque.get())
					.shortValue(), // inverse of major
					(byte) ~new Byte(dGramsQueuque.get()).shortValue())); // inverse of
																// minor

			// 32 bytes random
			tmpArr = new byte[32];
			dGramsQueuque.get(tmpArr);
			clientHello.setRandom(tmpArr);

			// 1 byte session_id_length
			clientHello.setSession_id_length(new Byte(dGramsQueuque.get()).shortValue());

			// if present, session_id_length bytes of session_id
			if (clientHello.getSession_id_length() > 0) {
				// read from the byte after id_length till to all the length
				tmpArr = new byte[clientHello.getSession_id_length()];
				dGramsQueuque.get(tmpArr);
				clientHello.setSession_id(tmpArr);
			}

			// 1 byte cookie_length
			// always present but after the possible session_id field
			clientHello.setCookie_length(new Byte(dGramsQueuque.get())
					.shortValue());

			// if present, cookie_length bytes of cookie
			if (clientHello.getCookie_length() > 0) {
				tmpArr = new byte[clientHello.getCookie_length()];
				dGramsQueuque.get(tmpArr);
				clientHello.setCookie(tmpArr);
			}

			// 2 bytes cypher_suites_length
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);
			clientHello.setCipher_suites_length((int) DTLSUtils.getValue(tmpArr));

			// if present, cypher_suites_length bytes of cypher_suites
			if (clientHello.getCipher_suites_length() > 0) {
				int[] cs = new int[clientHello.getCipher_suites_length()/2];
				//2 bytes each
				tmpArr = new byte[2];
				for (int i=0;i<cs.length;i++){
					//parse the cipher suite (2 bytes each)
					dGramsQueuque.get(tmpArr);
					cs[i] = (int)DTLSUtils.getValue(tmpArr); 
				}
				clientHello.setCipher_suites(cs);
			}

			// 1 byte compression_methods_length
			clientHello.setCompression_methods_length(new Byte(dGramsQueuque.get()).shortValue());

			// if present, compression_methods_length bytes of
			// compression_methods
			if (clientHello.getCompression_methods_length() > 0) {
				//1 byte each
				short[] cm = new short[clientHello.getCompression_methods_length()];
				for (int i=0; i<cm.length;i++){
					cm[i] = new Byte(dGramsQueuque.get()).shortValue();
				}
				clientHello.setCompression_methods(cm);
				// relative index not needed anymore
			}
			
			//parse extensions if present
			if (dGramsQueuque.hasRemaining()){
				//there are extensions present
				
				//2 bytes extensions length
				tmpArr = new byte[2];
				dGramsQueuque.get(tmpArr);
				clientHello.setExtensions_length((int)DTLSUtils.getValue(tmpArr));
				
				do{
					Extension ext = new Extension();
					//2 bytes type
					tmpArr = new byte[2];
					dGramsQueuque.get(tmpArr);
					ext.setType((int)DTLSUtils.getValue(tmpArr));

					//2 bytes extension length
					tmpArr = new byte[2];
					dGramsQueuque.get(tmpArr);
					ext.setExtensionLength((int)DTLSUtils.getValue(tmpArr));
					
					switch (ext.getType()) {
					case ExtensionType.elliptic_curves:
						Elliptic_Curve elliptic_curve = new Elliptic_Curve();
						
						//2 bytes list_length
						tmpArr = new byte[2];
						dGramsQueuque.get(tmpArr);
						//length not needed to be added; only used to parse
						int listLength = (int) DTLSUtils.getValue(tmpArr);
						
						//2 bytes per time read elliptic_curves
						for (int i = 0; i < listLength-1; i += 2){
							tmpArr = new byte[2];
							dGramsQueuque.get(tmpArr);
							elliptic_curve.add((int) DTLSUtils.getValue(tmpArr));
						}
						
						ext.setData(elliptic_curve);
						
						break;

					case ExtensionType.ec_point_formats:
						ECPointFormatList ecPointFormatList = new ECPointFormatList();
						
						//1 byte list_length
						//length not needed to be added; only used to parse
						short length = new Byte(dGramsQueuque.get()).shortValue();
						
						//1 byte per time read ec_point_formats 
						for (int i = 0; i < length; i ++){
							ecPointFormatList.add(new Byte(dGramsQueuque.get()).shortValue());
						}
						
						ext.setData(ecPointFormatList);

						break;
						
						//more extensions
						
					default:
						break;
					}
					
					//add the parsed extension
					clientHello.getExtensions().add(ext);
					
				}while(dGramsQueuque.hasRemaining());
				
			}
			
			return clientHello;
			
		case HandshakeType.hello_verify_request:
			HelloVerifyRequest helloVerifyRequest = new HelloVerifyRequest();
			
			// 2 bytes client_version
			helloVerifyRequest.setServer_version(new Version(
					(byte) ~new Byte(dGramsQueuque.get()).shortValue(), // inverse of major
					(byte) ~new Byte(dGramsQueuque.get()).shortValue())); // inverse of minor
			
			// 1 byte cookie_length
			// always present but after the possible session_id field
			helloVerifyRequest.setCookie_length(new Byte(dGramsQueuque.get())
					.shortValue());

			// if present, cookie_length bytes of cookie
			if (helloVerifyRequest.getCookie_length() > 0) {
				tmpArr = new byte[helloVerifyRequest.getCookie_length()];
				dGramsQueuque.get(tmpArr);
				helloVerifyRequest.setCookie(tmpArr);
				// relative index not needed anymore
			}
			return helloVerifyRequest;
			
		case HandshakeType.server_hello:
			ServerHello serverHello = new ServerHello();
			
			// 2 bytes client_version
			serverHello.setServer_version(new Version(
					(byte) ~new Byte(dGramsQueuque.get()).shortValue(), // inverse of major
					(byte) ~new Byte(dGramsQueuque.get()).shortValue())); // inverse of minor

			// 32 bytes random
			tmpArr = new byte[32];
			dGramsQueuque.get(tmpArr);
			serverHello.setRandom(tmpArr);
			
			// 1 byte session_id
			serverHello.setSession_id_length(new Byte(dGramsQueuque.get()).shortValue());

			// if present, session_id_length bytes of session_id
			if (serverHello.getSession_id_length() > 0) {
				// read from the byte after id_length till to all the length
				tmpArr = new byte[serverHello.getSession_id_length()];
				dGramsQueuque.get(tmpArr);
				serverHello.setSession_id(tmpArr);
			}	
			
			//2 bytes cipher_suite
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);			
			serverHello.setCipher_suite((int) DTLSUtils.getValue(tmpArr));
			
			//1 byte compression_method
			serverHello.setCompression_method(new Byte(dGramsQueuque.get()).shortValue());
			
			//parse extensions if present
			if (dGramsQueuque.hasRemaining()){
				//there are extensions present
				
				//2 bytes extensions length
				tmpArr = new byte[2];
				dGramsQueuque.get(tmpArr);
				serverHello.setExtensions_length((int)DTLSUtils.getValue(tmpArr));
				
				do{
					Extension ext = new Extension();
					//2 bytes type
					tmpArr = new byte[2];
					dGramsQueuque.get(tmpArr);
					ext.setType((int)DTLSUtils.getValue(tmpArr));

					//2 bytes extension length
					tmpArr = new byte[2];
					dGramsQueuque.get(tmpArr);
					ext.setExtensionLength((int)DTLSUtils.getValue(tmpArr));
					
					switch (ext.getType()) {
					case ExtensionType.elliptic_curves:
						Elliptic_Curve elliptic_curve = new Elliptic_Curve();
						
						//2 bytes list_length
						tmpArr = new byte[2];
						dGramsQueuque.get(tmpArr);
						//length not needed to be added; only used to parse
						int listLength = (int) DTLSUtils.getValue(tmpArr);
						
						//2 bytes per time read elliptic_curves
						for (int i = 0; i < listLength-1; i += 2){
							tmpArr = new byte[2];
							dGramsQueuque.get(tmpArr);
							elliptic_curve.add((int) DTLSUtils.getValue(tmpArr));
						}
						
						ext.setData(elliptic_curve);
						
						break;

					case ExtensionType.ec_point_formats:
						ECPointFormatList ecPointFormatList = new ECPointFormatList();
						
						//1 byte list_length
						//length not needed to be added; only used to parse
						short length = new Byte(dGramsQueuque.get()).shortValue();
						
						//1 byte per time read ec_point_formats 
						for (int i = 0; i < length; i ++){
							ecPointFormatList.add(new Byte(dGramsQueuque.get()).shortValue());
						}
						
						ext.setData(ecPointFormatList);

						break;
						
						//more extensions
						
					default:
						break;
					}
					
					//add the parsed extension
					serverHello.getExtensions().add(ext);
				}while(dGramsQueuque.hasRemaining());
				
			}
			
			return serverHello;
			
		case HandshakeType.certificate:
			Certificate certificate = new Certificate();
		
			//3 bytes certificates_length
			tmpArr = new byte[3];
			dGramsQueuque.get(tmpArr);
			certificate.setCertificates_length((int) DTLSUtils.getValue(tmpArr));
			
			//create the array of certificates
			ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();

			while (dGramsQueuque.position() < dGramsQueuque.limit()){
				//3 bytes certificate_length
				tmpArr = new byte[3];
				dGramsQueuque.get(tmpArr);
				int certLength = (int) DTLSUtils.getValue(tmpArr);
				
				//certificate_length bytes of certificate
				tmpArr = new byte[certLength];
				dGramsQueuque.get(tmpArr);
				
				certificates.add(decodeCertificate(tmpArr)); 
			}
			
			certificate.setCertificates(certificates);
			
			return certificate;
		
		case HandshakeType.server_key_exchange:
			ServerKeyExchange serverKeyExchange = new ServerKeyExchange();
			
			//TODO: make dynamic
			//case ec_diffie_hellman
			
			ECParameters curve_params = new ECParameters();
			
			//1 byte curve type
			curve_params.setCurve_type(new Byte(dGramsQueuque.get()).shortValue());

			//2 bytes named_curve
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);
			curve_params.setNamedCurve((int)DTLSUtils.getValue(tmpArr));
			
			ServerECDHParams params = new ServerECDHParams(curve_params);

			//1  bytes ec_point_length
			tmpArr = new byte[1];
			dGramsQueuque.get(tmpArr);
			params.setEcPointLength((int)DTLSUtils.getValue(tmpArr));			
			
			//variable ec_point
			tmpArr = new byte[params.getEcPointLength()];
			dGramsQueuque.get(tmpArr);
			params.setEcPoint(tmpArr);
			
			EC_DIFFIE_HELLMAN ecdh = new EC_DIFFIE_HELLMAN();
			ecdh.setParams(params);
			
			//2 bytes signature_length
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);
			ecdh.setSignatureLength((int)DTLSUtils.getValue(tmpArr));

			//variable signature
			tmpArr = new byte[ecdh.getSignatureLength()];
			dGramsQueuque.get(tmpArr);
			ecdh.setSignature(tmpArr);
			
			serverKeyExchange.setKeyExchange(ecdh);
			
			return serverKeyExchange;
		
		case HandshakeType.certificate_request:
			
			CertificateRequest certificateRequest = new CertificateRequest();
			
			//1 byte certificate_type_length
			short certificate_type_length = (short)dGramsQueuque.get();
			certificateRequest.setClientCertificateTypes_length(certificate_type_length);
			
			//1 byte each certificate_type
			short[] clientCertificateTypes = new short[certificate_type_length];
			for (int i = 0; i < certificate_type_length; i++) {
				clientCertificateTypes[i] = dGramsQueuque.get();
			}
			certificateRequest.setClientCertificateTypes(clientCertificateTypes);
			
			//2 bytes supported_signature_algorithms_length
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);
			int signatureAndHashAlgorithmsLength = (int) DTLSUtils.getValue(tmpArr);
			certificateRequest.setSignatureAndHashAlgorithms_length(signatureAndHashAlgorithmsLength);
			
			List<SignatureAndHashAlgorithm> sigAndHahs = new ArrayList<SignatureAndHashAlgorithm>();
			//for each signature and hash algorithm
			for (int i = 0; i < signatureAndHashAlgorithmsLength; i += 2) {
				//1 byte hash algorithm
				short hash = (short)dGramsQueuque.get(); 

				//1 byte signature algorithm
				short signature = (short)dGramsQueuque.get();
				
				sigAndHahs.add(new SignatureAndHashAlgorithm(hash, signature));			
			}
			certificateRequest.setSignatureAndHashAlgorithms(sigAndHahs);
			
			//2 bytes dn_total_length
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);
			int dnTotLength = (int) DTLSUtils.getValue(tmpArr);
			certificateRequest.setDistinguishedNames_length((int) DTLSUtils.getValue(tmpArr));
			
			List<DistinguishedName> dnList = new ArrayList<DistinguishedName>();
			//for each DN
			int bytesRead = 0;
			while (bytesRead < dnTotLength){
				//2 bytes length
				tmpArr = new byte[2];
				dGramsQueuque.get(tmpArr);
				int dnLength = (int) DTLSUtils.getValue(tmpArr);
				
				bytesRead+= 2;
				
				//DN
				tmpArr = new byte[dnLength];
				dGramsQueuque.get(tmpArr);
				byte[] dn = tmpArr;
				
				dnList.add(new DistinguishedName(dn));
				
				bytesRead+= dnLength;
				
			}
			certificateRequest.setDistinguishedNames(dnList);
			
			return certificateRequest;
			
		case HandshakeType.server_hello_done:
			// the message server_hello_done doesn't contain any body
			return null;
		case HandshakeType.certificate_verify:
			
			CertificateVerify certificateVerify = new CertificateVerify();
			
			//1 byte hash algorithm
			short hash = (short)dGramsQueuque.get(); 

			//1 byte signature algorithm
			short signature = (short)dGramsQueuque.get();
			
			certificateVerify.setSignatureAndHashAlgorithm(
					new SignatureAndHashAlgorithm(hash, signature));
			
			//2 bytes length
			tmpArr = new byte[2];
			dGramsQueuque.get(tmpArr);
			certificateVerify.setLength((int) DTLSUtils.getValue(tmpArr));
			
			//[length] bytes
			tmpArr = new byte[certificateVerify.getLength()];
			dGramsQueuque.get(tmpArr);
			certificateVerify.setSignatureOfMessagesHash(tmpArr);
			
			return certificateVerify;
			
		case HandshakeType.client_key_exchange:
			ClientKeyExchange clientKeyExchange = new ClientKeyExchange();
			
			//1 byte length
			tmpArr = new byte[1];
			dGramsQueuque.get(tmpArr);
			clientKeyExchange.setLength((int) DTLSUtils.getValue(tmpArr));
			
			//read length bytes
			tmpArr = new byte[clientKeyExchange.getLength()];
			dGramsQueuque.get(tmpArr);
			clientKeyExchange.setExchange_keys(tmpArr);
				
			return clientKeyExchange;
			
		case HandshakeType.finished:
			Finished finished = new Finished();
			
			//the whole body
			tmpArr = new byte[totalBodyLength];
			dGramsQueuque.get(tmpArr);
			finished.setFinished(tmpArr);
			
			return finished;

		default:
			return null;
		}
	}

	/**
	 * Decodes a X509 certificate from the byte array
	 * @param encodedCert
	 * @return
	 */
	private X509Certificate decodeCertificate(byte[] encodedCert) {
		ByteArrayInputStream bis = new ByteArrayInputStream(encodedCert);
        ASN1InputStream ais = new ASN1InputStream(bis);
        DERObject o;
        X509Certificate cert = null;
		try {
			o = ais.readObject();
			X509CertificateStructure chain = X509CertificateStructure.getInstance(o);

			CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
			
			// Read user Certificate 
			InputStream is1 = new 
					ByteArrayInputStream(chain.getEncoded()); 
			cert = (X509Certificate) cf.generateCertificate(is1); 
			is1.close();

//			System.out.println(eeCert);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}				

		return cert;
	}

	/**
	 * Parses the record layer fields and put them in the buffer.
	 * This is called to convert from Object to byte[]
	 * @param record
	 * @param buf
	 */
	private void parseRecordStaticFields(RecordLayer record,
			ByteBuffer buf) {
		// 1 byte content type
		buf.put(new Short(record.getContentType()).byteValue());
		
		// 2 bytes protocol version
		buf.put((byte) ~new Short(record.getProtocolVersion().getMajor()).byteValue());
		buf.put((byte) ~new Short(record.getProtocolVersion().getMinor()).byteValue());
		
		// 2 bytes epoch
		buf.put(DTLSUtils.getBytesFromValue(record.getEpoch(), 2));
		
		// 6 bytes sequence_number
		buf.put(DTLSUtils.getBytesFromValue(record.getSequence_number(), 6));
		
		// 2 bytes length
		buf.put(DTLSUtils.getBytesFromValue(record.getLength(), 2));
	}
	
	/**
	 * This method parses a fragment into a byte array.
	 * @param fragment
	 * @return
	 */
	public byte[] parseFragment(Fragment fragment) {
		ByteBuffer buf = ByteBuffer.allocate(fragment.getTotalByteLength());
		
		// 1 byte message type 
		buf.put(new Short(fragment.getMessage_type()).byteValue());
		
		// 3 bytes length
		buf.put(DTLSUtils.getBytesFromValue(fragment.getLength(), 3));

		// 2 bytes message_sequence
		buf.put(DTLSUtils.getBytesFromValue(fragment.getMessage_sequence(), 2));

		// 3 bytes fragment_offset
		buf.put(DTLSUtils.getBytesFromValue(fragment.getFragment_offset(), 3));

		// 3 bytes fragment_length
		buf.put(DTLSUtils.getBytesFromValue(fragment.getFragment_length(), 3));

		// body
		//can be null (finished)
		if (fragment.getBody() != null && fragment.getLength() > 0)
			buf.put(parseHandshake(fragment.getMessage_type(), fragment.getBody()));
		
		return Arrays.copyOfRange( buf.array(), 0, buf.position());
	}
	
	/**
	 * This method parses the record layer and returns a byte array
	 * to be sent to the client or server.
	 * 
	 * Encryption and compression is called before this method, so in this
	 * object it will be present an encrypted and compressed fragment, that
	 * has been already parsed in byte array, encrypted and compressed.
	 * So here it is needed to convert the rest of the fields of the record
	 * and append the fragment
	 * @param record
	 * @return
	 * @throws ProgramErrorException 
	 */
	public byte[] parseRecord(RecordLayer record) throws ProgramErrorException{
		
		ByteBuffer buf = ByteBuffer.allocate(record.getTotalByteLength()/* + record_iv_length*/);
		parseRecordStaticFields(record, buf);
		
		//put the encrypted and compressed fragment as it is
		//since it has been parsed before the encryption and compression
		buf.put(record.getEncryptedAndCompressedFragment());
		
		if (buf.array().length < 13)
			throw new ProgramErrorException("Error in parsing the record");
		
		return buf.array();
	}


	/**
	 * This method parses the incoming byte array dGram to recognise DTLS
	 * packets to be further processed
	 * 
	 * @param dGram the datagram packet containing DTLS
	 */
	public List<RecordLayer> parseDatagram(byte[] datagrams) {
		
		ByteBuffer dGramsQueuque = ByteBuffer.wrap(datagrams);
		
		//initialize the array list
		ArrayList<RecordLayer> records = new ArrayList<RecordLayer>();

		//the current record
		RecordLayer record;

		//if there are errors, return null
		//partial reading don't affect the DTLS mechanism
		try{
			
			//the record is composed by 13 bytes
			if (dGramsQueuque.capacity() < 13){
				// there are less bytes than the one composing a record layer
				return null;
			}
	
			//read the datagrams till to the end of the buffer
//			while(dGramsQueuque.position() < dGramsQueuque.capacity()){
			while(dGramsQueuque.hasRemaining()){
				
				record = new RecordLayer();
				
				// ContentType
				// RFC 5246 A.1
				//the record layer is composed by 13 bytes plus the fragment
				//so if there are less, there is an error
				//if there are at least 13 bytes and there are still bytes to read (position < capacity)
				// 1 byte containing the content_type
				record.setContentType(new Byte(dGramsQueuque.get()).shortValue());
				
				//if the content type doesn't match quit one of the possible types directly
				if (	(record.getContentType() != ContentType.handshake) &&
						(record.getContentType() != ContentType.application_data) &&
						(record.getContentType() != ContentType.alert) &&
						(record.getContentType() != ContentType.change_cipher_spec) ) 
					break;
				
				//create a new record to fill
				parseRecordStaticFields(dGramsQueuque, record);
				
				//if there are less bytes to read than length, the record is not complete
				if (record.getLength() > (dGramsQueuque.capacity() - dGramsQueuque.position()))
					return null;
				else{
					//put the length in the record to be eventually decrypted and decompressed
					byte[] encryptedAndCompressedFragment = new byte[record.getLength()];
					dGramsQueuque.get(encryptedAndCompressedFragment);
					record.setEncryptedAndCompressedFragment(encryptedAndCompressedFragment);
				}
				
				//add this record to the list of read records
				records.add(record);
				
			}
		}catch (Exception e) {
			//parsing not sucessfull
			System.out.println("Parsing error, skipping...");
		}
		return records;
	}

	/**
	 * This method parses from a buffer to a record object.
	 * Called when converting from byte[] to Object
	 * @param dGramsQueuque
	 * @param record
	 */
	private void parseRecordStaticFields(ByteBuffer dGramsQueuque, RecordLayer record) {
		
		//a temporary array to read from the buffer
		byte[] tmpArr;

		// 2 bytes ProtocolVersion
		record.setProtocolVersion(new Version((byte) ~new Byte(dGramsQueuque.get())
				.shortValue(), // inverse of major
				(byte) ~new Byte(dGramsQueuque.get()).shortValue())); // inverse of minor

		// 2 bytes epoch
		tmpArr = new byte[2];
		dGramsQueuque.get(tmpArr);
		record.setEpoch((int) DTLSUtils.getValue(tmpArr));

		// 6 bytes sequence_number
		tmpArr = new byte[6];
		dGramsQueuque.get(tmpArr);
		record.setSequence_number(DTLSUtils.getValue(tmpArr));

		// 2 bytes length
		tmpArr = new byte[2];
		dGramsQueuque.get(tmpArr);
		record.setLength((int) DTLSUtils.getValue(tmpArr));

	}

	public FragmentType parseFragment(byte[] buf) {
		
		ByteBuffer fragmentQueuque = ByteBuffer.wrap(buf);
		
		//the fragment to return
		Fragment fragment = new Fragment();
		//a temporary array to read from the buffer
		byte[] tmpArr;

		// 1 byte message type
		fragment.setMessage_type(new Byte(fragmentQueuque.get()).shortValue());
		
		// 3 bytes length
		tmpArr = new byte[3];
		fragmentQueuque.get(tmpArr);
		fragment.setLength((int) DTLSUtils.getValue(tmpArr));

		// 2 bytes message_sequence
		tmpArr = new byte[2];
		fragmentQueuque.get(tmpArr);
		fragment.setMessage_sequence((int) DTLSUtils.getValue(tmpArr));

		// 3 bytes fragment_offset
		tmpArr = new byte[3];
		fragmentQueuque.get(tmpArr);
		fragment.setFragment_offset((int) DTLSUtils.getValue(tmpArr));

		// 3 bytes fragment_length
		tmpArr = new byte[3];
		fragmentQueuque.get(tmpArr);
		fragment.setFragment_length((int) DTLSUtils.getValue(tmpArr));

		// body
		byte[] body = new byte[fragment.getLength()];
		
		fragmentQueuque.get(body);

		fragment.setBody(
				parseHandshake(fragment.getMessage_type(), fragment.getLength(), body));
		return fragment;
	}

	/**
	 * This method, depending on the content type, parses
	 * the payload of a Record Layer from a byte array to
	 * the correspondent object.
	 * This method MUST be called AFTER 
	 * RecordLayer.encodeAndEncryptRecord because it is supposed
	 * to have plaintext otherwise the parsing will not happen
	 * @param recordLayer
	 * @param decompressedFragment
	 * @return
	 */
	public FragmentType parseRecordPayloadBytes(short contentType,
			byte[] fragment) {

		// Fragment can be one of the following:
		switch (contentType) {
		case ContentType.handshake:
			// parse the handshake fragment
			return parseFragment(fragment);
			
		case ContentType.change_cipher_spec:
			
			ChangeCipherSpec changeCipherSpec = new ChangeCipherSpec();
			changeCipherSpec.setChange_cipher_spec(new Byte(fragment[0]).shortValue());
			return changeCipherSpec; 
			
		case ContentType.application_data:
			
			return new ApplicationData(fragment);
			
		case ContentType.alert:

			Alert alert = new Alert();
			alert.setAlertLevel(new Byte(fragment[0]).shortValue());
			alert.setAlertDescription(new Byte(fragment[1]).shortValue());
			return alert;
			
		default:
			/*
			 * unknown content type
			 * 
			 * RFC2246 page 13, ignore this state
			 */
			return null;
		}
	}

	/**
	 * This method parse the fragment in a byte array, depending
	 * on the record's content type. 
	 * @param recordLayer
	 * @param fragment
	 * @return
	 */
	public byte[] parseRecordPayload(short contentType,
			FragmentType fragment) {
		
		ByteBuffer buf = ByteBuffer.allocate(fragment.getTotalByteLength());

		switch (contentType) {
		
		case ContentType.handshake:
			// the fragment is a handshake
			buf.put(parseFragment((Fragment)fragment));
			break;
			
		case ContentType.change_cipher_spec:
			//the fragment is change_cipher_spec
			ChangeCipherSpec changeCipherSpec = (ChangeCipherSpec) fragment;
			buf.put(new Short(changeCipherSpec.getChange_cipher_spec()).byteValue());
			break;
			
		case ContentType.application_data:
			ApplicationData applicationData = (ApplicationData)fragment;
			buf.put(applicationData.getApplication_data());
			break;
			
		case ContentType.alert:
			
			Alert alert = (Alert)fragment;
			buf.put(new Short(alert.getAlertLevel()).byteValue());
			buf.put(new Short(alert.getAlertDescription()).byteValue());
			break;
			
		default:
			/*
			 * unknown content type
			 * 
			 * RFC2246 page 13, ignore this state
			 */
			break;
		}

		return buf.array();
	}

//	/**
//	 * This method return true if the byte array contains bytesPresent on the
//	 * array buf starting from the position pos
//	 * 
//	 * @param buf
//	 *            the array to analyze
//	 * @param pos
//	 *            starting position
//	 * @param bytesPresent
//	 *            number of bytes to check if contained in the array buf
//	 *            starting from the position pos
//	 * @return true if the buffer is bigger than pos + bytesPresent, false
//	 *         otherwise
//	 */
//	private boolean containsBytes(byte[] buf, int pos, int bytesPresent) {
//		return buf.length >= pos + bytesPresent ? true : false;
//	}


}
