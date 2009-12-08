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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import protocol.Protocol;
import protocol.client.KSAddRequest;


import sun.security.rsa.RSAKeyPairGenerator;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
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
	
	protected String password;
	
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

	protected RSAPrivateKey privateKey;	
	public RSAPrivateKey getPrivateKey() { return privateKey; }
	
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
			CipherPair kSessionCipher = authenticate(getKeyServer(), Constants.getKServerPrimaryKey());
			if(kSessionCipher != null) System.out.println("Key server session established.");
			
			//TODO: Retrieve keys from key server
			//TODO: Log in to chat server
			CipherPair cSessionCipher = authenticate(getChatServer(), Constants.getCServerPrimaryKey());
			if(cSessionCipher != null) System.out.println("Chat server session key established.");
		}
		else
		{
			CipherPair kSessionCipher = authenticate(getKeyServer(), Constants.getKServerPrimaryKey());
			if(kSessionCipher != null) System.out.println("Key server session established.");
			else return;
			generateKeys();
			promptForPassword();
			Protocol p = new KSAddRequest(userID, getPublicKey(), getPrivateKey(), password);
			boolean addSuccess = p.run(getKeyServer(), kSessionCipher);
			if(addSuccess) { System.out.println("User successfully added.");
			
			}
			//TODO: Generate keys
			//TODO: Add user to key server
			//TODO: Add + log in to chat server
			CipherPair cSessionCipher = authenticate(getChatServer(), Constants.getCServerPrimaryKey());
			if(cSessionCipher != null) System.out.println("Chat server session key established.");
		}
	}
	
	protected void promptForPassword()
	{
		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		boolean validPassword = false;
		while(!validPassword)
		{
			System.out.println("Please enter your password:");
			try { password = input.readLine(); } 
			catch (IOException e) { e.printStackTrace(); }
			// TODO: Add password validity tests.
			validPassword = true;
		}
	}
	
	protected void generateKeys()
	{
		RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
		gen.initialize(Constants.RSA_KEY_SIZE, new SecureRandom());
		KeyPair kp = gen.generateKeyPair();
		
		publicKey = (RSAPublicKey)kp.getPublic();
		privateKey = (RSAPrivateKey)kp.getPrivate();
	}
	
	public CipherPair authenticate(Socket server, RSAPublicKey serverKey)
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
			CipherPair sessionCipher = authenticateServerResponse(resp, kPair, serverKey);
			return sessionCipher;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		// Should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		// Return null if we escape the try
		return null;
	}
	
	public CipherPair authenticateServerResponse(ArrayList<byte[]> response, KeyPair ourKey, RSAPublicKey serverKey)
	{
		byte[] signedDHKeyHash = response.get(0);
		byte[] dhKeyBytes = response.get(1);
		byte[] iv = response.get(2);
		byte[] auth = response.get(3);
		
		// Authenticate the message.
		// Check the signature.
		if(!Common.verify(signedDHKeyHash, dhKeyBytes, serverKey))
		{
			System.err.println("Server key response did not match hash.");
			return null;
		}

		// Check the freshness.
		// Generate the session key.
		try 
		{
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dhKeyBytes);
	        KeyFactory keyFact = KeyFactory.getInstance("DH");
			PublicKey serverDHKey = keyFact.generatePublic(x509KeySpec);
			
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(ourKey.getPrivate());
			ka.doPhase(serverDHKey, true);
			
			// Generates a 256-bit secret by default.
			SecretKey sessionKey = ka.generateSecret(Constants.SESSION_KEY_ALG);
			// Simplify it to a 128-bit key for compatibility.
			// TODO: Is it secure to grab the first 16 bytes?
			sessionKey = 
				new SecretKeySpec(sessionKey.getEncoded(), 0, 16, Constants.SESSION_KEY_ALG);
			
			CipherPair sessionCipher = 
				new CipherPair(Constants.SESSION_KEY_ALG+Constants.SESSION_KEY_MODE, sessionKey);
			
			sessionCipher.initDecrypt(iv);
			byte[] authCheck = sessionCipher.decrypt.doFinal(auth);
			byte[] ourKeyBytes = ourKey.getPublic().getEncoded();
			if(!BufferUtils.equals(ourKeyBytes, authCheck))
			{
				System.err.println("Server authentication response did not match our key.");
				return null;
			}
			return sessionCipher;
		} 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeySpecException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		return null;
	}
}
