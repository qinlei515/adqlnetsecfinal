package protocol.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
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
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.Constants;
import utils.cserver.CServer;

public class CSAdd implements Protocol 
{
	byte[] name;
	
	CServer server;
	
	public CSAdd(byte[] name, CServer server)
	{
		this.name = name;
		this.server = server;
	}

	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket client, CipherPair sessionCipher) 
	{
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			DataInputStream fromClient = new DataInputStream(client.getInputStream());
			
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			
			if(server.userExists(BufferUtils.translateString(name)))
			{
				byte[] denial = Common.createMessage(Requests.DENY, name);
				byte[] encrDenial = sessionCipher.encrypt.doFinal(denial);
				byte[] mac = hmac.doFinal(denial);
				toClient.write(Common.createMessage(encrDenial, mac));
				return false;
			}
			
			byte[] salt = BufferUtils.random(2);
			
			{
				
				byte[] message = Common.createMessage(Requests.CONFIRM, name, salt);
				toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromClient);
				byte[] encrPwd = resp.get(0);
				byte[] mac = resp.get(1);
				byte[] pwdHash = Common.checkIntegrity(encrPwd, mac, hmac, sessionCipher);
				if(pwdHash == null)
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				MessageDigest pwdHasher = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM);
				byte[] pwd2Hash = pwdHasher.digest(pwdHash);
				server.addUser(BufferUtils.translateString(name), pwd2Hash, salt);
			}
			{
				byte[] confirm = Common.createMessage(name, Requests.ADD, Requests.CONFIRM);
				byte[] encrConfirm = sessionCipher.encrypt.doFinal(confirm);
				byte[] mac = hmac.doFinal(confirm);
				toClient.write(Common.createMessage(encrConfirm, mac));
				return true;
			}
		} 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		
		return false;
	}

}
