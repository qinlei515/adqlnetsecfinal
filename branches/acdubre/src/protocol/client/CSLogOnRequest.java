package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.Mac;

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
 * Client side of a client-server protocol. Attempts to log the specified user off 
 * from the chat server.
 * 
 * @author Alex Dubreuil, Lei Qin
 *
 */
public class CSLogOnRequest implements Protocol 
{
	String name;
	String password;
	ClientUser thisUser;
	
	public CSLogOnRequest(String name, String password, ClientUser thisUser)
	{
		this.name = name;
		this.password = password;
		this.thisUser = thisUser;
	}
	
	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket server, CipherPair sessionCipher) 
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(server.getOutputStream());
			DataInputStream fromServer = new DataInputStream(server.getInputStream());
			
			Mac hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			sessionCipher.initEncrypt();
			MessageDigest pwdHasher = MessageDigest.getInstance(CipherInfo.PWD_HASH_ALGORITHM);
			
			{
				byte[] message = Common.createMessage(Requests.LOG_ON, name.getBytes());
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
				byte[] name = resp.get(0);
				if(!BufferUtils.equals(name, this.name.getBytes()))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				byte[] salt = resp.get(1);
				
				byte[] pwdPlusSalt = BufferUtils.concat(password.getBytes(), salt);
				byte[] pwdHash = pwdHasher.digest(pwdPlusSalt);
				byte[] ipAddress = server.getLocalAddress().getAddress();
				message = Common.createMessage(this.name.getBytes(), pwdHash, ipAddress);
				toServer.write(Common.wrapMessage(message, hmac, sessionCipher));
			}
			{
				boolean moreUsers = true;
				while(moreUsers)
				{
					ArrayList<byte[]> resp = Common.getResponse(fromServer);
					byte[] message = Common.checkIntegrity(resp, hmac, sessionCipher);
					if(message == null)
					{
						System.err.println("Integrity check failed.");
						return false;
					}
					resp = Common.splitResponse(message);
					byte[] userOrEnd = resp.get(0);
					if(BufferUtils.equals(userOrEnd, Requests.LOG_ON))
					{
						String name = BufferUtils.translateString(resp.get(1));
						byte[] ip = resp.get(2);
						thisUser.addUser(name, BufferUtils.translateIPAddress(ip));
					}
					else
					{
						moreUsers = false;
						thisUser.setSequence(resp.get(1));
						thisUser.incrementSequence();
					}
				}
				return true;
			}
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); }
		catch (ConnectionClosedException e) {
			try { server.close(); }
			catch (IOException e1) {
				e1.printStackTrace();
			}
		} 
		return false;
	}

}
