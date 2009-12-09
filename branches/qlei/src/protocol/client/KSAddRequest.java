package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Constants;


public class KSAddRequest implements Protocol
{
	MessageDigest pwdHasher;
	String name;
	byte[] pubKey;
	byte[] encryptedPrivateKey;
	String password; 
	     
	public KSAddRequest(String name, RSAPublicKey pubKey, RSAPrivateKey privKey, String password)
	{
		this.name = name;
		this.pubKey = pubKey.getEncoded();
		this.password = password;
		try 
		{
			Cipher pwdCipher = 
				Cipher.getInstance(Constants.SESSION_KEY_ALG+Constants.SESSION_KEY_MODE);
			this.pwdHasher = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM);
			byte[] privKeyKey = pwdHasher.digest(password.getBytes());
			pwdCipher.init(Cipher.ENCRYPT_MODE, 
					new SecretKeySpec(privKeyKey, 0, 16, Constants.SESSION_KEY_ALG));
			byte[] iv = pwdCipher.getIV();
			this.encryptedPrivateKey = Common.createMessage(iv, pwdCipher.doFinal(privKey.getEncoded()));
			
		}
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (NoSuchPaddingException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); }
	}
	
	public boolean run(Socket server, CipherPair sessionCipher) 
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(server.getOutputStream());
			DataInputStream fromServer = new DataInputStream(server.getInputStream());
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			sessionCipher.initEncrypt();
			
			{
				byte[] message = Common.createMessage(Requests.ADD, 
						name.getBytes(), pubKey, encryptedPrivateKey);
				byte[] iv = sessionCipher.encrypt.getIV();
				toServer.write(Common.wrapMessage(message, iv, hmac, sessionCipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromServer);
				byte[] encrMessage = resp.get(0);
				byte[] mac = resp.get(1);
				byte[] message = sessionCipher.decrypt.doFinal(encrMessage);
				
				ArrayList<byte[]> splitMessage = Common.splitResponse(message);
				byte[] allowed = splitMessage.get(0);
				byte[] name = splitMessage.get(1);
				
				byte[] checkMac = hmac.doFinal(message);
				
				if(!BufferUtils.equals(mac, checkMac) 
						|| !BufferUtils.equals(name, this.name.getBytes()))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				if(BufferUtils.equals(allowed, Requests.DENY))
				{
					System.out.println("User already in use (key), cannot be created.");
					return false;
				}
				
				byte[] salt = splitMessage.get(2);
				
				byte[] pwdSalt = BufferUtils.concat(password.getBytes(), salt);
				// TODO: Hash again to match the proposed protocol, now unnecessary.
				byte[] pwdHash = 
					MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM).digest(pwdSalt);
				byte[] pwdMac = hmac.doFinal(pwdHash);
				byte[] encrPwdHash = sessionCipher.encrypt.doFinal(pwdHash);
				toServer.write(Common.createMessage(encrPwdHash, pwdMac));
			}
			{
				ArrayList<byte[]> confirmation = Common.getResponse(fromServer);
				byte[] decryptedConfirm = sessionCipher.decrypt.doFinal(confirmation.get(0));
				confirmation = Common.splitResponse(decryptedConfirm);
				
				if(BufferUtils.equals(name.getBytes(), confirmation.get(0))
						&& BufferUtils.equals(Requests.ADD, confirmation.get(1))
						&& BufferUtils.equals(Requests.CONFIRM, confirmation.get(2)))
					return true;
			}
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); }
		catch (BadPaddingException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); }
		
		return false;
	}
	
}
