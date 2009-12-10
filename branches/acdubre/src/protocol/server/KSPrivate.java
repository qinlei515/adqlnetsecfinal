package protocol.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
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
import utils.constants.CipherInfo;
import utils.exceptions.ConnectionClosedException;
import utils.kserver.KServer;

/**
 * Response to a KSPrivateRequest. Retrieves a user's private key.
 * 
 * @author Alex Dubreuil
 *
 */
public class KSPrivate implements Protocol 
{
	byte[] name;
	KServer server;

	public KSPrivate(byte[] name, KServer server)
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
			
			Mac hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			MessageDigest pwdHasher = MessageDigest.getInstance(CipherInfo.PWD_HASH_ALGORITHM);
			
			{
				byte[] salt = server.getSalt(BufferUtils.translateString(name));
				byte[] message;
				if(salt == null)
				{
					message = Common.createMessage(Requests.DENY, name);
					return false;
				}
				else
				{
					message = Common.createMessage(Requests.CONFIRM, name, salt);
				}
				System.out.println("Sending salt or denial.");
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
				if(!BufferUtils.equals(this.name, name))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				byte[] pwd2Hash = pwdHasher.digest(pwdHash);
				byte[] privKeyBytes = 
					server.getPrivate(BufferUtils.translateString(name), pwd2Hash);
				if(privKeyBytes == null)
				{
					message = Common.createMessage(Requests.DENY, name);
					toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
					return false;
				}
				message = Common.createMessage(Requests.CONFIRM, privKeyBytes);
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
