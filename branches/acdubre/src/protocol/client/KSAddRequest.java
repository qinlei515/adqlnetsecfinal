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
			this.encryptedPrivateKey = pwdCipher.doFinal(privKey.getEncoded()); 
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
				byte[] encrMessage = sessionCipher.encrypt.doFinal(message);
				byte[] mac = hmac.doFinal(message);
				
				toServer.write(Common.createMessage(iv, encrMessage, mac));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromServer);
				byte[] encrMessage = resp.get(0);
				byte[] mac = resp.get(1);
				byte[] message = sessionCipher.decrypt.doFinal(encrMessage);
				
				ArrayList<byte[]> splitMessage = Common.splitResponse(message);
				byte[] name = splitMessage.get(0);
				byte[] salt = splitMessage.get(1);
				
				byte[] checkMac = hmac.doFinal(message);
				
				if(!BufferUtils.equals(mac, checkMac) 
						|| !BufferUtils.equals(name, this.name.getBytes()))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				
				byte[] pwdSalt = BufferUtils.concat(password.getBytes(), salt);
				// TODO: Hash again to match the proposed protocol, now unnecessary.
				byte[] pwdHash = 
					MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM).digest(pwdSalt);
				byte[] pwdMac = hmac.doFinal(pwdHash);
				byte[] encrPwdHash = sessionCipher.encrypt.doFinal(pwdHash);
				toServer.write(Common.createMessage(encrPwdHash, pwdMac));
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
