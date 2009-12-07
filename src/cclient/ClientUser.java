package cclient;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.SecretKey;

import protocol.client.Common;

import utils.BufferUtils;
import utils.Constants;

public class ClientUser 
{
	public static final String DEFAULT_CHAT_SERVER = "127.0.0.1";
	public static final String DEFAULT_KEY_SERVER = "127.0.0.1"; 
	
	public ClientUser()
	{
		connections = new TreeMap<String, Socket>();
		activeUsers = new TreeMap<String, InetAddress>();
		setChatServer(DEFAULT_CHAT_SERVER);
		setKeyServer(DEFAULT_KEY_SERVER);
	}
	
	protected String userID;
	
	public String getUserID() { return userID; }
	public void setUserID(String uid) { this.userID = uid; }
	
	protected Socket chatServer;
	
	public Socket getChatServer() { return chatServer; }
	public void setChatServer(String chatServerIP) 
	{ 
		try { this.chatServer = new Socket(chatServerIP, Constants.CHAT_SERVER_PORT); } 
		catch (UnknownHostException e) { System.err.println(e.getMessage() + "\n"); } 
		catch (IOException e) { System.err.println(e.getMessage() + "\n"); } 
	}
	
	protected Socket keyServer;
	
	public Socket getKeyServer() { return keyServer; }
	public void setKeyServer(String keyServerIP) 
	{ 	
		try { this.keyServer = new Socket(keyServerIP, Constants.KEY_SERVER_PORT); } 
		catch (UnknownHostException e) { System.err.println(e.getMessage() + "\n"); } 
		catch (IOException e) { System.err.println(e.getMessage() + "\n"); }
	}
	
	protected Map<String, Socket> connections;
	
	public boolean addConnection(String user, Socket location)
	{
		if(connections.containsKey(user))
		{
			System.err.println("Cannot create connection to " + user + ": connection already exists.");
			return false;
		}
		else
		{
			connections.put(user, location);
			return true;
		}
	}
	
	public boolean closeConnection(String user)
	{
		if(!connections.containsKey(user))
		{
			System.err.println("Cannot close connection to " + user + ": no connection exists.");
			return false;
		}
		else
		{
			connections.remove(user);
			return true;
		}
	}
	
	protected TreeMap<String, InetAddress> activeUsers;
	
	public TreeMap<String, InetAddress> getUsers() { return activeUsers; }
	public void addUser(String uid, InetAddress addr) { activeUsers.put(uid, addr); }
	public void removeUser(String uid) { activeUsers.remove(uid); }
	

	protected RSAPublicKey publicKey;	
	public RSAPublicKey getPublicKey() { return publicKey; }
	public void setPublicKey(PublicKey key) { publicKey = (RSAPublicKey)key; }

	protected RSAPrivateKey privateKey;	
	public RSAPrivateKey getPrivateKey() { return privateKey; }
	public void setPrivateKey(PrivateKey key) { privateKey = (RSAPrivateKey)key; }
	
	/**
	 * Get the username if it hasn't been entered.
	 * Connect to the key server:
	 * - Retrieve keys if possible
	 * - Set keys otherwise
	 * Connect to the chat server:
	 * - Login + populate the activeUsers Map 
	 */
	public void initialize()
	{
		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		while("".equals(userID) || userID == null)
		{
			System.out.println("Please enter your user name.");
			System.out.print("> ");
			try { userID = input.readLine(); } 
			catch (IOException e) { e.printStackTrace(); }
			if("".equals(userID) || userID == null)
				System.out.println("Username error.");
		}
		System.out.println("Have you used this name before? (y/n)");
		String answer = "";
		//TODO: Commented to speed testing.
//		try { answer = input.readLine(); }
//		catch(IOException e) { e.printStackTrace(); }
		if("y".equals(answer))
		{
			
			SecretKey kSessionKey = authenticate(getKeyServer(), Constants.getKServerPrimaryKey());
			if(kSessionKey != null) System.out.println("Key server session established.");
			//TODO: Retrieve keys from key server
			//TODO: Log in to chat server
			SecretKey cSessionKey = authenticate(getChatServer(), Constants.getCServerPrimaryKey());
			if(cSessionKey != null) System.out.println("Chat server session key established.");
		}
		else
		{
			SecretKey sessionKey = authenticate(getKeyServer(), Constants.getKServerPrimaryKey());
			if(sessionKey != null) System.out.println("Key server session established.");
			//TODO: Generate keys
			//TODO: Add user to key server
			//TODO: Add + log in to chat server
			SecretKey cSessionKey = authenticate(getChatServer(), Constants.getCServerPrimaryKey());
			if(cSessionKey != null) System.out.println("Chat server session key established.");
		}
	}
	
	public SecretKey authenticate(Socket server, RSAPublicKey serverKey)
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(server.getOutputStream());
			DataInputStream fromServer = new DataInputStream(server.getInputStream());
			
			KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
			dhGen.initialize(Constants.getDHParameters());
			KeyPair kPair = dhGen.generateKeyPair();
			PublicKey pubKey = kPair.getPublic();
		
			toServer.write(Common.createMessage(pubKey.getEncoded(), Constants.getKServerKeyHash()));
			// TODO: For simplicity, we currently assume we will receive the challenge from the server.
			toServer.write(Common.handleChallenge2(fromServer));
			
			ArrayList<byte[]> resp = Common.getResponse(fromServer);
			if(BufferUtils.equals(resp.get(0), Constants.SERVER_KEY_RESET))
			{
				//TODO: Update the server's primary and secondary public keys.
			}			
			SecretKey sessionKey = Common.authenticateServerResponse(resp, kPair, serverKey);
			return sessionKey;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		// Should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		// Return null if we escape the try
		return null;
	}
}
