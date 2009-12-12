package utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.Mac;

import utils.constants.CipherInfo;
import utils.exceptions.ConnectionClosedException;

/**
 * A structure for representation a connection between to clients.
 * Used to watch the connection for incoming messages.
 *
 */
public class Connection implements Runnable
{
	public Socket s;
	public Mac hmac;
	public CipherPair cipher;
	private String name;
	
	public Connection(Socket s, CipherPair cipher)
	{
		this(s);
		this.cipher = cipher;
		try
		{
			hmac = Mac.getInstance(CipherInfo.HMAC_SHA1_ALG);
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
	
	public void setName(String name) { this.name = name; }
	
	
	/**
	 * Watch this connection until it is closed.
	 */
	public void run() 
	{
		try {
			s.setSoTimeout(100);
			DataInputStream in = new DataInputStream(s.getInputStream()); 
			while(!s.isClosed())
			{
				try 
				{
					ArrayList<byte[]> message = Common.getResponse(in);
					byte[] data = Common.checkIntegrity(message, hmac, cipher);
					if(data != null) 
						System.out.println(name + " says " + BufferUtils.translateString(data));
				}
				catch (SocketException e) { System.err.println(name + "'s socket closed."); }
				catch (SocketTimeoutException e) {}
				catch (IOException e) { e.printStackTrace(); }
				catch (ConnectionClosedException e) 
				{
					s.close();
				}
			}
		}
		catch (IOException e) { e.printStackTrace(); }
	}
}
