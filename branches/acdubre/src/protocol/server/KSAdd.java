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
import utils.Constants;
import utils.kserver.KServer;
import utils.kserver.UserKeyData;

public class KSAdd implements Protocol 
{
	protected byte[] name;
	protected byte[] pubKey;
	protected byte[] encrPrivKey;
	protected byte[] pwd3Hash;
	
	protected KServer server;
	
	protected Mac hmac;
	
	public KSAdd(byte[] name, byte[] pubKey, byte[] encrPrivKey, KServer server)
	{
		this.name = name;
		this.pubKey = pubKey;
		this.encrPrivKey = encrPrivKey;
		this.server = server;
		
		try { hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
	}
	
	public boolean run(Socket client, CipherPair sessionCipher) 
	{
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			DataInputStream fromClient = new DataInputStream(client.getInputStream());
			
			hmac.init(sessionCipher.key);
		
			byte[] salt = BufferUtils.random(2);
			byte[] message = Common.createMessage(name, salt);
			byte[] mac = hmac.doFinal(message);
			byte[] encrMessage = sessionCipher.encrypt.doFinal(message);
			
			byte[] m = Common.createMessage(encrMessage, mac);
			toClient.write(m);
			ArrayList<byte[]> resp = Common.getResponse(fromClient);
			byte[] encrPwdHash = resp.get(0);
			byte[] pwdMac = resp.get(1);
			byte[] pwdHash = sessionCipher.decrypt.doFinal(encrPwdHash);
			byte[] checkPwdMac = hmac.doFinal(pwdHash);
			if(!BufferUtils.equals(pwdMac, checkPwdMac))
			{
				System.err.println("Integrity check failed.");
				return false;
			}
			byte[] pwd2Hash = MessageDigest.getInstance(Constants.PWD_HASH_ALGORITHM).digest(pwdHash);
			UserKeyData user = new UserKeyData(salt, pwd2Hash, pubKey, encrPrivKey);
			server.addUser(BufferUtils.translateString(name), user);
			byte[] confirmation = Common.createMessage(name, Requests.ADD, Requests.CONFIRM);
			byte[] encrConfirm = sessionCipher.encrypt.doFinal(confirmation);
			toClient.write(Common.createMessage(encrConfirm));
			return true;
		} 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		catch (IOException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		
		return false;
	}

}
