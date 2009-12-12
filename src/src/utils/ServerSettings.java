package utils;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import utils.constants.CipherInfo;

/**
 * Stores the critical information about a server - IP address and port, RSA keys and key hash.
 */
public class ServerSettings 
{
	protected String ipAddress;
	public String getIP() { return ipAddress; }
	
	protected int port;	
	public int getPort() { return port; }
	
	protected Socket toServer;
	public Socket connection() 
	{
		if(!toServer.isConnected())
		{
			try { this.toServer = new Socket(ipAddress, port); } 
			catch (UnknownHostException e) { System.err.println(e.getMessage() + "\n"); } 
			catch (IOException e) { System.err.println(e.getMessage() + "\n"); }
		}
		return toServer;
	}
	public void close()
	{
		if(!toServer.isClosed())
			try { toServer.close(); } 
			catch (IOException e) { e.printStackTrace(); }
	}
	
	protected RSAPublicKey primary;
	public RSAPublicKey getPrimary() { return primary; }
	
	protected RSAPublicKey secondary;
	public RSAPublicKey getSecondary() { return secondary; }
	
	protected byte[] primaryKeyHash;
	public byte[] getKeyHash() { return primaryKeyHash; }
	
	public ServerSettings(int port, String ip, RSAPublicKey primary, RSAPublicKey secondary)
	{
		this.port = port;
		this.ipAddress = ip;
		this.primary = primary;
		try 
		{
			this.primaryKeyHash = MessageDigest.getInstance(CipherInfo.DH_HASH_ALG).digest(primary.getEncoded());
		} 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		this.secondary = secondary;
	}
	
	public ServerSettings(int port, String ip, String primaryFile, String secondaryFile)
	{
		this.port = port;
		this.ipAddress = ip;
		try
		{
			try
			{
				File keyFile = new File(primaryFile);
				FileInputStream keyInFile = new FileInputStream(keyFile);
				DataInputStream keyIn = new DataInputStream(keyInFile);
				byte[] keyBytes = new byte[(int)keyFile.length()];
				keyIn.read(keyBytes);
				keyIn.close();
				keyInFile.close();
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
				this.primary = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(keySpec);
				this.primaryKeyHash = MessageDigest.getInstance(CipherInfo.DH_HASH_ALG).digest(primary.getEncoded());
			}
			catch(FileNotFoundException e) { System.err.println("Server key file: " + primaryFile + " not found."); }
			try
			{
				File keyFile = new File(secondaryFile);
				FileInputStream keyInFile = new FileInputStream(keyFile);
				DataInputStream keyIn = new DataInputStream(keyInFile);
				byte[] keyBytes = new byte[(int)keyFile.length()];
				keyIn.read(keyBytes);
				keyIn.close();
				keyInFile.close();
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
				this.secondary = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(keySpec);
			}
			catch(FileNotFoundException e) { System.err.println("Server key file: " + secondaryFile + " not found."); }
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidKeySpecException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
	}
}
