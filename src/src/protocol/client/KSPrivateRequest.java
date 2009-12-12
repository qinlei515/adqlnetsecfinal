package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import cclient.ClientUser;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.constants.CipherInfo;
import utils.exceptions.ConnectionClosedException;

/**
 * Attempts to retrieve the specified user's private key from the key server.
 *
 */
public class KSPrivateRequest implements Protocol 
{
	String name;
	String password;
	ClientUser user;
	
	public KSPrivateRequest(String password, ClientUser user)
	{
		this.name = user.getUserID();
		this.password = password;
		this.user = user;
	}
	
	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket server, CipherPair sessionCipher) 
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(server.getOutputStream());
			DataInputStream fromServer = new DataInputStream(server.getInputStream());
			
			MessageDigest pwdHasher = MessageDigest.getInstance(CipherInfo.PWD_HASH_ALGORITHM);
			
			Mac hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			sessionCipher.initEncrypt();
			
			{
				byte[] message = Common.createMessage(Requests.PRIVATE, name.getBytes());
				byte[] iv = sessionCipher.encrypt.getIV();
				toServer.write(Common.wrapMessage(message, iv, hmac, sessionCipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromServer);
				byte[] message = Common.checkIntegrity(resp, hmac, sessionCipher);
				if(message == null)
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				resp = Common.splitResponse(message);
				byte[] exists = resp.get(0);
				if(BufferUtils.equals(exists, Requests.DENY))
				{
					System.out.println("User does not exist on key server.");
					return false;
				}
				byte[] name = resp.get(1);
				if(!BufferUtils.equals(name, this.name.getBytes()))
				{
					System.out.println("Integrity check failed.");
					return false;
				}
				byte[] salt = resp.get(2);
				
				
				byte[] pwdPlusSalt = BufferUtils.concat(password.getBytes(), salt);
				byte[] pwdHash = pwdHasher.digest(pwdPlusSalt);
				message = Common.createMessage(name, pwdHash);
				toServer.write(Common.wrapMessage(message, hmac, sessionCipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromServer);
				byte[] message = Common.checkIntegrity(resp, hmac, sessionCipher);
				if(message == null)
				{
					System.out.println("Integrity check failed.");
					return false;
				}
				resp = Common.splitResponse(message);
				if(BufferUtils.equals(resp.get(0), Requests.DENY))
				{
					System.out.println("User's password did not match the server.");
					return false;
				}
				byte[] encrKeyBytes = resp.get(1);
				Cipher pwdCipher = 
					Cipher.getInstance(CipherInfo.SESSION_KEY_ALG+CipherInfo.SESSION_KEY_MODE);
				pwdHasher = MessageDigest.getInstance(CipherInfo.PWD_HASH_ALGORITHM);
				byte[] privKeyKey = pwdHasher.digest(password.getBytes());
				ArrayList<byte[]> keyInfo = Common.splitResponse(encrKeyBytes);
				byte[] iv = keyInfo.get(0);
				byte[] encrKey = keyInfo.get(1);
				pwdCipher.init(Cipher.DECRYPT_MODE, 
						new SecretKeySpec(privKeyKey, 0, 16, CipherInfo.SESSION_KEY_ALG),
						new IvParameterSpec(iv));
				byte[] privKeyBytes = pwdCipher.doFinal(encrKey);
				user.setKey(privKeyBytes);
				return true;
			}
		} 
		catch (IOException e) { e.printStackTrace(); }
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		catch (InvalidKeyException e) { e.printStackTrace(); }
		catch (NoSuchPaddingException e) { e.printStackTrace(); }
		catch (IllegalBlockSizeException e) { e.printStackTrace(); }
		catch (BadPaddingException e) { e.printStackTrace(); }
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		catch (IndexOutOfBoundsException e) { System.err.println("Connection error."); }
		catch (ConnectionClosedException e) {
			try { server.close(); }
			catch (IOException e1) {
				e1.printStackTrace();
			}
		}
		return false;
	}

}
