package utils;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

public class Constants 
{
	public static final int CHAT_SERVER_PORT = 6417;
	public static final int KEY_SERVER_PORT = 6473;
	public static final int RSA_KEY_SIZE = 1024;
	public static final int RSA_BLOCK_SIZE = 128;
	
	public static final int CHALLENGE_BYTESIZE = 2;
	
	public static final String SESSION_KEY_ALG = "AES";
	public static final String SESSION_KEY_MODE = "/CBC/ISO10126Padding";
	public static Cipher SESSION_CIPHER;
	
	public static Cipher sessionCipher()
	{
		if(SESSION_CIPHER == null)
		{
			try { SESSION_CIPHER = Cipher.getInstance(SESSION_KEY_ALG+SESSION_KEY_MODE); }
			// Should be unreachable
			catch(NoSuchAlgorithmException e) { e.printStackTrace(); } 
			catch (NoSuchPaddingException e) { e.printStackTrace();	}
		}
		return SESSION_CIPHER;
	}
	
	public static final String SIGNATURE_ALG = "SHA1withRSA";
	
	public static final String CHALLENGE_HASH_ALG = "SHA1";
	private static MessageDigest CHALLENGE_HASH;
	public static final int C_HASH_SIZE = 40;
	
	public static MessageDigest challengeHash()
	{
		if(CHALLENGE_HASH == null)
		{
			try { CHALLENGE_HASH = MessageDigest.getInstance(CHALLENGE_HASH_ALG); } 
			// Should be unreachable.
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return CHALLENGE_HASH;
	}
	
	public static final String DH_HASH_ALG = "SHA1";
	private static MessageDigest DH_HASH;
	public static final int DH_HASH_SIZE = 40;
	
	public static MessageDigest dhHash()
	{
		if(DH_HASH == null)
		{
			try { DH_HASH = MessageDigest.getInstance(DH_HASH_ALG); } 
			// Should be unreachable.
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return DH_HASH;
	}
	
	
	private static KeyFactory RSA_KEY_FACTORY;
	
	public static KeyFactory getRSAKeyFactory()
	{
		if(RSA_KEY_FACTORY == null)
		{
			try { RSA_KEY_FACTORY = KeyFactory.getInstance("RSA"); } 
			// Should be unreachable.
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return RSA_KEY_FACTORY;
	}
	
	private static KeyFactory DH_KEY_FACTORY;
	
	public static KeyFactory getDHKeyFactory()
	{
		if(DH_KEY_FACTORY == null)
		{
			try { DH_KEY_FACTORY = KeyFactory.getInstance("DH"); } 
			// Should be unreachable.
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return DH_KEY_FACTORY;
	}
	
	private static RSAPublicKey CSERVER_PRIMARY_KEY;
	private static byte[] CSERVER_KEY_HASH;
	private static final String CSERVER_PRIMARY_KEY_FILE = "keys/cPrimaryPub.key";
	
	public static byte[] getCServerKeyHash()
	{
		if(CSERVER_KEY_HASH == null)
			CSERVER_KEY_HASH = getCServerPrimaryKey().getEncoded();
		return CSERVER_KEY_HASH;
	}
	
	public static RSAPublicKey getCServerPrimaryKey()
	{
		if(CSERVER_PRIMARY_KEY == null)
		{
			try
			{
				File keyFile = new File(CSERVER_PRIMARY_KEY_FILE);
				FileInputStream keyInFile = new FileInputStream(keyFile);
				DataInputStream keyIn = new DataInputStream(keyInFile);
				byte[] keyBytes = new byte[(int)keyFile.length()];
				keyIn.read(keyBytes);
				keyIn.close();
				keyInFile.close();
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
				CSERVER_PRIMARY_KEY = 
					(RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(keySpec);
			}
			catch(FileNotFoundException e) { System.err.println("Chat server key file not found!"); } 
			catch (IOException e) { e.printStackTrace(); } 
			catch (InvalidKeySpecException e) { e.printStackTrace(); } 
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return CSERVER_PRIMARY_KEY;
	}
	
	private static RSAPublicKey KSERVER_PRIMARY_KEY;
	private static byte[] KSERVER_KEY_HASH;
	private static final String KSERVER_PRIMARY_KEY_FILE = "keys/kPrimaryPub.key";
	
	public static byte[] getKServerKeyHash()
	{
		if(KSERVER_KEY_HASH == null)
			KSERVER_KEY_HASH = getKServerPrimaryKey().getEncoded();
		return KSERVER_KEY_HASH;
	}
	
	public static RSAPublicKey getKServerPrimaryKey()
	{
		if(KSERVER_PRIMARY_KEY == null)
		{
			try
			{
				File keyFile = new File(KSERVER_PRIMARY_KEY_FILE);
				FileInputStream keyInFile = new FileInputStream(keyFile);
				DataInputStream keyIn = new DataInputStream(keyInFile);
				byte[] keyBytes = new byte[(int)keyFile.length()];
				keyIn.read(keyBytes);
				keyIn.close();
				keyInFile.close();
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
				KSERVER_PRIMARY_KEY = 
					(RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(keySpec);
			}
			catch(FileNotFoundException e) { System.err.println("Key server key file not found!"); } 
			catch (IOException e) { e.printStackTrace(); } 
			catch (InvalidKeySpecException e) { e.printStackTrace(); } 
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return KSERVER_PRIMARY_KEY;
	}
	
	private static DHParameterSpec DH_PARAMETERS;
	private static final String DH_PARAMETERS_FILE = "keys/dh.params";
	
	public static DHParameterSpec getDHParameters()
	{
		if(DH_PARAMETERS == null)
		{
			try
			{
				File paramFile = new File(DH_PARAMETERS_FILE);
				FileInputStream paramInFile = new FileInputStream(paramFile);
				InputStreamReader paramIn = new InputStreamReader(paramInFile);
				BufferedReader paramReader = new BufferedReader(paramIn);
				BigInteger p = new BigInteger(paramReader.readLine());
				BigInteger g = new BigInteger(paramReader.readLine());
				DH_PARAMETERS = new DHParameterSpec(p, g);
				paramReader.close();
				paramIn.close();
				paramInFile.close();
			}
			catch(FileNotFoundException e) { System.err.println("Diffie-Hellman parameters file not found."); }
			catch(IOException e) { e.printStackTrace(); }
		}
		return DH_PARAMETERS;
	}

	public static final byte[] SERVER_KEY_RESET = "SKRESET".getBytes();
}
