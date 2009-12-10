package protocol.server;


import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Constants;
import utils.Password;
import utils.cserver.CServer;

public class CSLogOff implements Protocol {

	protected byte[] name;
	protected byte[] pwdHash;
	protected CServer server;
	
	/* Password is actually a data structure including twice hash of password,
	 * rather than password itself */
	protected Password pwd;
	
	public CSLogOff(byte[] name, byte[] pwdHash, CServer server)
	{
		this.name = name;
		this.pwdHash = pwdHash;
		this.server = server;
		this.pwd = server.getUser(BufferUtils.translateString(name));
	}
	
	@Override
	public boolean run(Socket client, CipherPair sessionCipher) {
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			MessageDigest pwdHasher = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM);
			
			byte[] pwd2Hash = pwdHasher.digest(pwdHash);
			if(!BufferUtils.equals(pwd2Hash, pwd.pwd2Hash))
			{
				System.err.println("Logoff: user authentication failed.");
				byte[] message = Common.createMessage(Requests.DENY);
				toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
				return false;
			}
			byte[] message = Common.createMessage(Requests.CONFIRM);
			toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
			server.logOffUser(BufferUtils.translateString(name));
			return true;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		return false;
	}

}
