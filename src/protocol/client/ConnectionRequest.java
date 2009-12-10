package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
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
import javax.crypto.Cipher;
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
import utils.Constants;

/**
 * Build a connection between two users.
 */
public class ConnectionRequest implements Protocol 
{
	ClientUser user;
	String destName;
	RSAPublicKey destKey;
	
	public ConnectionRequest(String destName, ClientUser user) 
	{
		this.destName = destName;
		this.destKey = user.getPublicKey(destName);
		this.user = user;
	}

	public boolean run(Connection c) 
	{
		try 
		{
			c.s = new Socket(user.getUsers().get(destName), Constants.MESSAGE_PORT);
			DataOutputStream toDest = new DataOutputStream(c.s.getOutputStream());
			DataInputStream fromDest = new DataInputStream(c.s.getInputStream());
			
			KeyPair kPair;
			PublicKey theirDHKey;
			{
				KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
				dhGen.initialize(Constants.getDHParameters());
				kPair = dhGen.generateKeyPair();
				PublicKey ourPubKey = kPair.getPublic();
				
				toDest.write(user.authenticateToClient(ourPubKey, destKey));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromDest);
				resp = user.unwrapClientAuthMessage(resp);
				byte[] name = resp.get(0);
				byte[] dhPubKey = resp.get(1);
				byte[] signed = resp.get(2);
				if(!Common.verify(signed, dhPubKey, destKey) 
						|| !BufferUtils.equals(name, destName.getBytes()))
				{
					System.out.println("Authentication failed.");
					return false;
				}
				
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dhPubKey);
		        KeyFactory keyFact = KeyFactory.getInstance("DH");
		        theirDHKey = keyFact.generatePublic(x509KeySpec);
		        
		        // Set up the private key.
				KeyAgreement ka = KeyAgreement.getInstance("DH");
				ka.init(kPair.getPrivate());
				ka.doPhase(theirDHKey, true);
				
				// Generates a 256-bit secret by default.
				SecretKey sessionKey = ka.generateSecret(Constants.SESSION_KEY_ALG);
				Cipher cEncrypt = new CipherPair(Constants.SESSION_KEY_ALG+Constants.SESSION_KEY_MODE, 
						new SecretKeySpec(sessionKey.getEncoded(), 0, 16, Constants.SESSION_KEY_ALG)).encrypt;
				c.hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
				c.hmac.init(sessionKey);
				
				c.cipher.initEncrypt();
				byte[] iv = cEncrypt.getIV();
				byte[] message = Common.createMessage(Requests.CONFIRM, 
						user.getUserID().getBytes(), theirDHKey.getEncoded());
				byte[] encrMessage = c.cipher.encrypt.doFinal(message);
				toDest.write(Common.wrapMessage(encrMessage, iv, c.hmac, c.cipher));
				resp = Common.getResponse(fromDest);
				c.cipher = user.authenticateResponse(resp, kPair, destKey);
				c.cipher.encrypt = cEncrypt;
			}
		}
		catch (UnknownHostException e) { e.printStackTrace(); }
		catch (IOException e) { e.printStackTrace(); }
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
		return false;
	}

}
