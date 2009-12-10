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
import utils.Constants;

public class CSLogOffRequest implements Protocol {

	String name;
	String password;
	byte[] salt;
	ClientUser thisUser;
	
	public CSLogOffRequest(String name, String password, byte[] salt, ClientUser thisUser)
	{
		this.name = name;
		this.password = password;
		this.salt = salt;
		this.thisUser = thisUser;
	}
	
	@Override
	public boolean run(Socket server, CipherPair sessionCipher) {
		try 
		{
			DataOutputStream toServer = new DataOutputStream(server.getOutputStream());
			DataInputStream fromServer = new DataInputStream(server.getInputStream());
			
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			sessionCipher.initEncrypt();
			MessageDigest pwdHasher = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM);
			
			{
				byte[] pwdPlusSalt = BufferUtils.concat(password.getBytes(), salt);
				byte[] pwdHash = pwdHasher.digest(pwdPlusSalt);
				byte[] message = Common.createMessage(Requests.LOG_OFF, name.getBytes(), pwdHash);
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
				byte[] confirm = resp.get(0);
				if(!BufferUtils.equals(confirm, Requests.CONFIRM))
				{
					System.err.println("Log off failed.");
					return false;
				}
				return true;
			}
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		return false;
	}

}
