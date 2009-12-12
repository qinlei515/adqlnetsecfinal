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
import utils.Connection;
import utils.Password;
import utils.constants.CipherInfo;
import utils.cserver.CServer;
import utils.exceptions.ConnectionClosedException;

/**
 * A response to a log on request. Adds the a user to the active user map.
 *
 */
public class CSLogOn implements Protocol 
{
	protected byte[] name;
	protected Password pwd;
	protected CServer server;
	
	public CSLogOn(byte[] name, CServer server)
	{
		this.name = name;
		this.pwd = server.getUser(BufferUtils.translateString(name));
		this.server = server;
	}
	
	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket client, CipherPair sessionCipher) 
	{
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			DataInputStream fromClient = new DataInputStream(client.getInputStream());
			
			Mac hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			MessageDigest pwdHasher = MessageDigest.getInstance(CipherInfo.PWD_HASH_ALGORITHM);
			
			if(pwd == null)
			{
				System.err.println("User does not exist, cannot log in.");
				return false;
			}
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
				// Alert everyone that a new user has logged in.
				server.sequenceIncrement();
				new ChatLogBroadcast(server,
						BufferUtils.translateString(name),
						ipAddress,
						Requests.LOG_ON).run(null, null);
				server.updateUser(BufferUtils.translateString(name), ipAddress);

				// Give the user the current list of logged in users.
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
		catch (ConnectionClosedException e) {
			try { client.close(); }
			catch (IOException e1) {
				e1.printStackTrace();
			}
		} 
		return false;
	}
}
