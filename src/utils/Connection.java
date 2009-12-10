package utils;

import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public class Connection
{
	public Socket s;
	public Mac hmac;
	public CipherPair cipher;
	
	public Connection(Socket s, CipherPair cipher)
	{
		this.s = s;
		this.cipher = cipher;
		try
		{
			hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(cipher.key);
		}
		catch(NoSuchAlgorithmException e) { e.printStackTrace(); }
		catch (InvalidKeyException e) { e.printStackTrace(); }
	}
	
	public Connection() {}
}
