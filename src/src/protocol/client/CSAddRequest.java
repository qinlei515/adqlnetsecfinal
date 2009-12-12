package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.Common;
import utils.Connection;
import utils.constants.CipherInfo;
import utils.exceptions.ConnectionClosedException;

/**
 * Client side of a client-server protocol. Attempt to add a user to the chat server.
 *
 */
public class CSAddRequest implements Protocol 
{
	protected String name;
	protected String password;
	
	
	public CSAddRequest(String name, String password)
	{
		this.name = name;
		this.password = password;
	}
	
	public boolean run(Connection c) 
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(c.s.getOutputStream());
			DataInputStream fromServer = new DataInputStream(c.s.getInputStream());
			
			Mac hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
			hmac.init(c.cipher.key);
			c.cipher.initEncrypt();
			
			{
				byte[] message = Common.createMessage(Requests.ADD, name.getBytes());
				byte[] iv = c.cipher.encrypt.getIV();
				toServer.write(Common.wrapMessage(message, iv, hmac, c.cipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromServer);
				byte[] encrMessage = resp.get(0);
				byte[] mac = resp.get(1);
				byte[] message = c.cipher.decrypt.doFinal(encrMessage);
				resp = Common.splitResponse(message);
				byte[] allowed = resp.get(0);
				byte[] nameCheck = resp.get(1);
				byte[] salt = resp.get(2);
				byte[] checkMac = hmac.doFinal(message);

				if(!BufferUtils.equals(mac, checkMac) 
						|| !BufferUtils.equals(nameCheck, name.getBytes()))
				{
					System.out.println("Integrity check failed.");
					return false;
				}
				if(BufferUtils.equals(allowed, Requests.DENY))
				{
					System.out.println("User already in use (chat), cannot be created.");
					return false;
				}
				
				byte[] pwdPlusSalt = BufferUtils.concat(password.getBytes(), salt);
				MessageDigest pwdHasher = MessageDigest.getInstance(CipherInfo.PWD_HASH_ALGORITHM);
				byte[] pwdHash = pwdHasher.digest(pwdPlusSalt);
				byte[] pwdMac = hmac.doFinal(pwdHash);
				byte[] encrPwd = c.cipher.encrypt.doFinal(pwdHash);
				
				toServer.write(Common.createMessage(encrPwd, pwdMac));
			}
			{
				ArrayList<byte[]> confirm = Common.getResponse(fromServer);
				byte[] encrConfirm = confirm.get(0);
				byte[] mac = confirm.get(1);
				byte[] confMessage = c.cipher.decrypt.doFinal(encrConfirm);
				byte[] checkMac = hmac.doFinal(confMessage);
				
				if(!BufferUtils.equals(mac, checkMac))
				{
					System.out.println("Integrity check failed.");
					return false;
				}
				
				confirm = Common.splitResponse(confMessage);
				if(BufferUtils.equals(confirm.get(0), name.getBytes())
						&& BufferUtils.equals(confirm.get(1), Requests.ADD)
						&& BufferUtils.equals(confirm.get(2), Requests.CONFIRM))
					return true;
				
			}
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); }
		catch (ConnectionClosedException e) {
			try { c.s.close(); }
			catch (IOException e1) {
				e1.printStackTrace();
			}
		}
		
		
		return false;
	}

}
