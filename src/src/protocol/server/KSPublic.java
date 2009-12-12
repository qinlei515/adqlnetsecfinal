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
import utils.Connection;
import utils.constants.CipherInfo;
import utils.kserver.KServer;

/**
 * Response to a KSPublic request (you're sensing a pattern, aren't you?).
 * Retrieves a user's public key.
 *
 */
public class KSPublic implements Protocol {

	protected byte[] ctname;
	protected KServer server;
	
	public KSPublic(byte[] ctname, KServer server)
	{
		this.ctname = ctname;
		this.server = server;
	}
	
	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket client, CipherPair sessionCipher) {
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			
			Mac hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			
			MessageDigest md = MessageDigest.getInstance(CipherInfo.DH_HASH_ALG);
			byte[] skhash = md.digest(sessionCipher.key.getEncoded());
			
			if (!server.userExists(BufferUtils.translateString(ctname)))
			{
				//TODO send client a message telling that username does not exist
				byte[] message = Common.createMessage(Requests.DENY, ctname);
				toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
				return false;
			}
			byte[] pubKey = server.getPubKey(BufferUtils.translateString(ctname));
			byte[] message = Common.createMessage(Requests.CONFIRM, pubKey, skhash);
			toClient.write(Common.wrapMessage(message, hmac, sessionCipher));
			return true;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		
		return false;
	}

}
