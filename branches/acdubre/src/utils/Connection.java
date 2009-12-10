package utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.Mac;

public class Connection implements Runnable
{
	public Socket s;
	public Mac hmac;
	public CipherPair cipher;
	private boolean open;
	private String name;
	
	public Connection(Socket s, CipherPair cipher)
	{
		this(s);
		this.cipher = cipher;
		try
		{
			hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(cipher.key);
		}
		catch(NoSuchAlgorithmException e) { e.printStackTrace(); }
		catch (InvalidKeyException e) { e.printStackTrace(); }
	}
	
	public Connection(Socket s)
	{
		this.s = s;
	}
	
	public Connection() {}

	public void close() { open = false; }
	public void setName(String name) { this.name = name; }
	
	public void run() 
	{
		try {
			DataInputStream in = new DataInputStream(s.getInputStream()); 
			open = true;
			while(open)
			{
				try 
				{
					ArrayList<byte[]> message = Common.getResponse(in);
					byte[] data = Common.checkIntegrity(message, hmac, cipher);
					if(data != null) 
						System.out.println(name + " says " + BufferUtils.translateString(data));
				}
				catch (IOException e) {
					e.printStackTrace();
				}

			}
		}
		catch (IOException e) { e.printStackTrace(); }
	}
}
