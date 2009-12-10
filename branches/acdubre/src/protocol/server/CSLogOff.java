package protocol.server;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.Mac;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.Constants;
import utils.Password;
import utils.cserver.CServer;

public class CSLogOff implements Protocol {

	protected byte[] name;
	protected CServer server;
	
	/* Password is actually a data structure including twice hash of password,
	 * rather than password itself */
	protected Password pwd;
	
	public CSLogOff(byte[] name, CServer server)
	{
		this.name = name;
		this.server = server;
		this.pwd = server.getUser(BufferUtils.translateString(name));
	}
	

	public boolean run(Connection c) { return run(c.s, c.cipher, c.hmac); }
	
	public boolean run(Socket client, CipherPair sessionCipher, Mac hmac) 
	{
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			DataInputStream fromClient = new DataInputStream(client.getInputStream());
			
			MessageDigest pwdHasher = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM);
			byte[] ipAddress;
			
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
				ipAddress = resp.get(2);
//				byte[] ipAddress = client.getInetAddress().getAddress();
				if(!BufferUtils.equals(name, this.name))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				byte[] pwd2Hash = pwdHasher.digest(pwdHash);
				if(!BufferUtils.equals(pwd2Hash, pwd.pwd2Hash))
				{
					System.err.println("Logoff: user authentication failed.");
					message = Common.createMessage(Requests.DENY);
					toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
					return false;
				}
			}
			byte[] message = Common.createMessage(Requests.CONFIRM);
			toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
			server.logOffUser(BufferUtils.translateString(name));
			server.sequenceIncrement();
			// Tell all users.
			return new ChatLogBroadcast(server, BufferUtils.translateString(name), ipAddress, Requests.LOG_OFF).run(new Connection());
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		return false;
	}

}
