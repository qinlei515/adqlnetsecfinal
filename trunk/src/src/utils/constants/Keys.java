package utils.constants;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.DHParameterSpec;

/**
 * Interfaces for clients retrieving server keys.
 */
public class Keys 
{
	/** Keys */
	private static final String CSERVER_PRIMARY_KEY_FILE = "keys/cPrimaryPub.key";
	private static final String KSERVER_PRIMARY_KEY_FILE = "keys/kPrimaryPub.key";
	private static final String DH_PARAMETERS_FILE = "keys/dh.params";
	
	
	/** Chat server key and hash */
	private static RSAPublicKey CSERVER_PRIMARY_KEY;
	private static byte[] CSERVER_KEY_HASH;
	
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
	
	/** Key server key and hash */
	
	private static RSAPublicKey KSERVER_PRIMARY_KEY;
	private static byte[] KSERVER_KEY_HASH;
	
	
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
	
	/** DH parameters */
	
	private static DHParameterSpec DH_PARAMETERS;
	
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
}
