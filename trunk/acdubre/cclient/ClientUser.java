package cclient;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class ClientUser 
{
	protected String userID;
	
	public String getUserID() { return userID; }
	public void setUserID(String uid) { this.userID = uid; }
	
	protected Socket chatServer;
	
	public Socket getChatServer() { return chatServer; }
	public void setChatServerIP(String chatServerIP) 
	{ 
		try { this.chatServer = new Socket(chatServerIP, utils.Constants.CHAT_SERVER_PORT); } 
		catch (UnknownHostException e) { System.err.println(e.getMessage() + "\n"); } 
		catch (IOException e) { System.err.println(e.getMessage() + "\n"); } 
	}
	
	protected Socket keyServer;
	
	public Socket getKeyServer() { return keyServer; }
	public void setKeyServer(String keyServerIP) 
	{ 	
		try { this.keyServer = new Socket(keyServerIP, utils.Constants.KEY_SERVER_PORT); } 
		catch (UnknownHostException e) { System.err.println(e.getMessage() + "\n"); } 
		catch (IOException e) { System.err.println(e.getMessage() + "\n"); }
	}
	
//	X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
//	publicKey = (RSAPublicKey)kFactory.generatePublic(keySpec);
	protected RSAPublicKey publicKey;
	
	public RSAPublicKey getPublicKey() { return publicKey; }
	public void setPublicKey(PublicKey key) { publicKey = (RSAPublicKey)key; }

//	PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
//	privateKey = (RSAPrivateKey)kFactory.generatePrivate(keySpec);
	protected RSAPrivateKey privateKey;
	
	public RSAPrivateKey getPrivateKey() { return privateKey; }
	public void setPrivateKey(PrivateKey key) { privateKey = (RSAPrivateKey)key; }
}
