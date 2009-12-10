package utils.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Constants;

/**
 * Stores critical data for a server, implements behavior common to all servers.
 */
public class Server 
{
	protected int port;
	public int getPort() { return port; }
	
	protected RSAPrivateKey primary;
	
	protected RSAPublicKey primaryPub;
	public RSAPublicKey getPrimaryPub() { return primaryPub; }
	
	protected byte[] primaryKeyHash;
	public byte[] getPrimaryKeyHash() { return primaryKeyHash; }
	
	protected RSAPrivateKey secondary;
	
	protected ServerSocket connectionAccepter;
	public ServerSocket getAccepter() { return connectionAccepter; }
	public void acceptConnections()
	{
		try { connectionAccepter = new ServerSocket(port); } 
		catch (IOException e) { e.printStackTrace(); }
	}
	public void stopAcceptingConnections()
	{
		try { connectionAccepter.close(); } 
		catch (IOException e) { e.printStackTrace(); }
	}
	
	protected ServerBehavior behavior;
	public ServerBehavior getBehavior() { return behavior; }
	
	public Server(int port, ServerBehavior behavior, String primaryFile, String primaryPubFile, String secondaryFile)
	{
		this.port = port;
		this.behavior = behavior;
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
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
				this.primary = (RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(keySpec);
			}
			catch(FileNotFoundException e) { System.err.println("Server key file: " + primaryFile + " not found."); }
			try
			{
				File keyFile = new File(primaryPubFile);
				FileInputStream keyInFile = new FileInputStream(keyFile);
				DataInputStream keyIn = new DataInputStream(keyInFile);
				byte[] keyBytes = new byte[(int)keyFile.length()];
				keyIn.read(keyBytes);
				keyIn.close();
				keyInFile.close();
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
				this.primaryPub = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(keySpec);
			}
			catch(FileNotFoundException e) { System.err.println("Server key file: " + primaryPubFile + " not found."); }
//			try
//			{
//				File keyFile = new File(secondaryFile);
//				FileInputStream keyInFile = new FileInputStream(keyFile);
//				DataInputStream keyIn = new DataInputStream(keyInFile);
//				byte[] keyBytes = new byte[(int)keyFile.length()];
//				keyIn.read(keyBytes);
//				keyIn.close();
//				keyInFile.close();
//				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
//				this.secondary = (RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(keySpec);
//			}
//			catch(FileNotFoundException e) { System.err.println("Server key file: " + secondaryFile + " not found."); }
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidKeySpecException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
	}
	
	public byte[] sign(byte[] toSign)
    {
    	return Common.sign(toSign, primary);
    }
	
	public CipherPair authenticate(Socket client)
	{
		try 
		{
			DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
			DataInputStream fromClient = new DataInputStream(client.getInputStream());
			
			ArrayList<byte[]> resp1 = Common.getResponse(fromClient);
			byte[] clientKeyBytes = resp1.get(0);
			if(!BufferUtils.equals(resp1.get(1), Constants.getKServerKeyHash()))
			{
				//TODO: Run the key overwrite protocol.
			}
			// Send guess-the-number challenge
			byte[] challengeNumber = BufferUtils.random(Constants.CHALLENGE_BYTESIZE);
			toClient.write(Common.createMessage(createChallenge(challengeNumber)));
			byte[] resp2 = Common.getResponse(fromClient).get(0);
			if(!BufferUtils.equals(resp2, challengeNumber))
			{
				//TODO: Inform the client + Terminate the connection.
			}	
			// Set up the client's DH public key
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientKeyBytes);
	        KeyFactory keyFact = KeyFactory.getInstance("DH");
			PublicKey clientDHKey = keyFact.generatePublic(x509KeySpec);
			
			// Create the server's DH key
			// TODO: Reuse to decrease server load.
			KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
			dhGen.initialize(Constants.getDHParameters());
			
			KeyPair kPair = dhGen.generateKeyPair();
			
			// Set up the private key.
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(kPair.getPrivate());
			ka.doPhase(clientDHKey, true);
			
			// Generates a 256-bit secret by default.
			SecretKey sessionKey = ka.generateSecret(Constants.SESSION_KEY_ALG);
			// Simplify it to a 128-bit key for compatibility.
			// TODO: Is it secure to grab the first 16 bytes?
			sessionKey = new SecretKeySpec(sessionKey.getEncoded(), 0, 16, Constants.SESSION_KEY_ALG);
			
			// Sign & send to client
			byte[] pubKeyBytes = kPair.getPublic().getEncoded();
			byte[] signedHash = sign(pubKeyBytes);
			
			CipherPair sessionCipher = 
				new CipherPair(Constants.SESSION_KEY_ALG+Constants.SESSION_KEY_MODE, sessionKey);
			sessionCipher.initEncrypt();
			byte[] iv = sessionCipher.encrypt.getIV();
			byte[] auth = sessionCipher.encrypt.doFinal(clientKeyBytes);
			toClient.write(Common.createMessage(signedHash, pubKeyBytes, iv, auth));
			
			return sessionCipher;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		catch (InvalidKeySpecException e) { e.printStackTrace(); }
		catch (IndexOutOfBoundsException e) { System.err.println("Invalid user response."); }
		// Should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); }  
		// Return null if we escape the try
		return null;
	}
	
	
	//TODO: Redo this as UDP instead of TCP
	public boolean provideChallenge1(Socket client) throws IOException
	{
		DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
		DataInputStream fromClient = new DataInputStream(client.getInputStream());
		{
			byte[] challenge1 = calculateChallenge1(client);
			toClient.write(challenge1);
		}
		byte[] response1 = Common.getResponse(fromClient).get(0);
		return BufferUtils.equals(response1, calculateChallenge1(client));
	}
	
	protected byte[] calculateChallenge1(Socket client)
	{
		byte[] cAddr = client.getInetAddress().getAddress();
		MessageDigest md;
		try 
		{
			md = MessageDigest.getInstance(Constants.CHALLENGE_HASH_ALG);
			md.update(BufferUtils.concat(cAddr, utils.kserver.KSConstants.C_1_SECRET));
			return md.digest();
		} 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		return null;
	}
	
	public ArrayList<byte[]> createChallenge(byte[] number)
	{
		ArrayList<byte[]> answer = new ArrayList<byte[]>();
		try
		{
			answer.add(MessageDigest.getInstance(Constants.CHALLENGE_HASH_ALG).digest(number));
		}
		catch(NoSuchAlgorithmException e) { e.printStackTrace(); }
		
		byte[] maskedNumber = new byte[number.length];
		for(int i = 0; i < number.length/2; i++)
			maskedNumber[i] = 0;
		answer.add(maskedNumber);
		return answer;
	}
	
	public void run()
	{
		acceptConnections();
		while(true)
		{
			try { synchronized(this) { this.wait(1); }} 
			catch (InterruptedException e) { e.printStackTrace(); }
			try 
			{ 
				Socket connection = getAccepter().accept();
				new Thread(new ConnectionHandler(connection, this)).run();
			} 
			catch (IOException e) { e.printStackTrace(); }
		}
	}
}
