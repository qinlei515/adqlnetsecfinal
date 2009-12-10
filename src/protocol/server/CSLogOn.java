package protocol.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;

import javax.crypto.Mac;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Constants;
import utils.Password;
import utils.cserver.CServer;

public class CSLogOn implements Protocol 
{
	protected byte[] name;
	/* Password is actually a data structure including twice hash of password,
	 * rather than password itself */
	protected Password pwd;
	protected CServer server;
	
	public CSLogOn(byte[] name, CServer server)
	{
		this.name = name;
		this.pwd = server.getUser(BufferUtils.translateString(name));
		this.server = server;
	}
	
	public boolean run(Socket client, CipherPair sessionCipher) 
	{
		try 
		{
			if(pwd == null)
			{
				System.err.println("User does not exist, cannot log in.");
				return false;
			}
			
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			DataInputStream fromClient = new DataInputStream(client.getInputStream());
			
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			MessageDigest pwdHasher = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM);
			
			{
				byte[] salt = pwd.salt;
				byte[] message = Common.createMessage(name, salt);
				toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromClient);
				byte[] message = Common.checkIntegrity(resp, hmac, sessionCipher);
				if(message == null)
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				resp = Common.splitResponse(message);
				byte[] name = resp.get(0);
				byte[] pwdHash = resp.get(1);
				byte[] ipAddress = resp.get(2);
//				byte[] ipAddress = client.getInetAddress().getAddress();
				if(!BufferUtils.equals(name, this.name))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				byte[] pwd2Hash = pwdHasher.digest(pwdHash);
				if(!BufferUtils.equals(pwd2Hash, pwd.pwd2Hash))
				{
					System.err.println("User authentication failed.");
					//TODO: Politely tell the user?
					return false;
				}
					
				server.updateUser(BufferUtils.translateString(name), ipAddress);
				server.sequenceIncrement();
				Map<String, byte[]> onlineUsers = server.getOnlineUsers();
				for(String user : onlineUsers.keySet())
				{
					byte[] ip = onlineUsers.get(user);
					message = Common.createMessage(Requests.LOG_ON, user.getBytes(), ip);
					toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
				}
				message = Common.createMessage(Requests.LOG_OFF, server.sequence());
				toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
				return true;
			}
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		return false;
	}
}
