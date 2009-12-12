package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import cclient.ClientUser;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.constants.CipherInfo;
import utils.constants.Keys;
import utils.exceptions.ConnectionClosedException;

/**
 * Client-client protocol. Accepts a connection from another client.
 * 
 * Adds a Connection to this user's connections map that matches the Connection
 * set up by the Requesting client.
 *
 */
public class ConnectionAccept implements Protocol 
{
	ClientUser user;
	
	public ConnectionAccept(ClientUser user)
	{
		this.user = user;
	}
	
	public boolean run(Connection c) 
	{
		System.out.println("New incoming connection.");
		try 
		{
			DataOutputStream toSrc = new DataOutputStream(c.s.getOutputStream());
			DataInputStream fromSrc = new DataInputStream(c.s.getInputStream());
			
			KeyPair kPair;
			PublicKey ourDHKey;
			PublicKey theirDHKey;
			RSAPublicKey srcKey;
			
			byte[] srcName;
			
			{
				// A->B: {A, [ga mod p]prka}pkb
				ArrayList<byte[]> request = Common.getResponse(fromSrc);
				request = user.unwrapClientAuthMessage(request);
				srcName = request.get(0);
				byte[] dhPubKey = request.get(1);
				byte[] signed = request.get(2);
				srcKey = user.getPublicKey(BufferUtils.translateString(srcName));
				System.out.println("Authenticating incoming connection.");
				if(!Common.verify(signed, dhPubKey, srcKey))
				{
					System.out.println("Authentication failed.");
					return false;
				}
				
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dhPubKey);
		        KeyFactory keyFact = KeyFactory.getInstance("DH");
		        theirDHKey = keyFact.generatePublic(x509KeySpec);
				
				KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
				dhGen.initialize(Keys.getDHParameters());
				
				kPair = dhGen.generateKeyPair();
				ourDHKey = kPair.getPublic();
				
				// B->A: {B, [gb mod p]prka}pka
				toSrc.write(user.authenticateToClient(ourDHKey, srcKey));
				
				// Set up the private key.
				KeyAgreement ka = KeyAgreement.getInstance("DH");
				ka.init(kPair.getPrivate());
				ka.doPhase(theirDHKey, true);
				
				// Generates a 256-bit secret by default.
				SecretKey sessionKey = ka.generateSecret(CipherInfo.SESSION_KEY_ALG);
				sessionKey = 
					new SecretKeySpec(sessionKey.getEncoded(), 0, 16, CipherInfo.SESSION_KEY_ALG);
				
				c.cipher = 
					new CipherPair(CipherInfo.SESSION_KEY_ALG+CipherInfo.SESSION_KEY_MODE, sessionKey);
				c.cipher.initEncrypt();
				
				c.hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
				c.hmac.init(sessionKey);
			}
			{
				// Get the other side's IV
				ArrayList<byte[]> resp = Common.getResponse(fromSrc);
				
				byte[] iv = resp.get(0);
				byte[] encrMessage = resp.get(1);
				byte[] mac = resp.get(2);
				
				c.cipher.initDecrypt(iv);
				byte[] message = c.cipher.decrypt.doFinal(encrMessage);
			
				if(!BufferUtils.equals(mac, c.hmac.doFinal(message)))
				{
					System.err.println("Accept: Failed integrity check.");
					return false;
				}
				
				resp = Common.splitResponse(message);
				byte[] confirm = resp.get(0);
				byte[] name = resp.get(1);
				byte[] dhKey = resp.get(2);
				if(!BufferUtils.equals(confirm, Requests.LOG_ON)
						|| !BufferUtils.equals(name, srcName)
						|| !BufferUtils.equals(dhKey, ourDHKey.getEncoded()))
				{
					System.err.println("Accept: Failed integrity check.");
					return false;
				}
			}
			{
				c.cipher.initEncrypt();
				
				byte[] iv = c.cipher.encrypt.getIV();
				byte[] message = Common.createMessage(Requests.CONFIRM, 
						user.getUserID().getBytes(), theirDHKey.getEncoded());
				
				// Give the other side our IV
				toSrc.write(Common.wrapMessage(message, iv, c.hmac, c.cipher));
			}
			user.addConnection(BufferUtils.translateString(srcName), c);
			c.setName(BufferUtils.translateString(srcName));
			new Thread(c).start();
			return true;
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		catch (BadPaddingException e) {
			e.printStackTrace();
		}
		catch (ConnectionClosedException e) {
			try { c.s.close(); }
			catch (IOException e1) {
				e1.printStackTrace();
			}
		}
		
		return false;
	}

}
