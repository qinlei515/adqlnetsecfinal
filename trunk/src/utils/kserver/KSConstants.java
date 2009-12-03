package utils.kserver;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class KSConstants 
{
	//TODO: Make this an actual secret that changes over time.
	public static byte[] C_1_SECRET = "I know, you know.".getBytes();
	
	private static RSAPrivateKey SERVER_PRIVATE_KEY;
	private static String SERVER_PRIVATE_KEY_FILE = "serverPrivate.key";
	
	public static RSAPrivateKey serverPrivateKey()
	{
		if(SERVER_PRIVATE_KEY == null)
		{
			try
			{
				File keyFile = new File(SERVER_PRIVATE_KEY_FILE);
				FileInputStream keyInFile = new FileInputStream(keyFile);
				DataInputStream keyIn = new DataInputStream(keyInFile);
				byte[] keyBytes = new byte[(int)keyFile.length()];
				keyIn.read(keyBytes);
				keyIn.close();
				keyInFile.close();
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
				SERVER_PRIVATE_KEY = (RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(keySpec);
			}
			catch(FileNotFoundException e) { System.err.println("Server key file not found!"); } 
			catch (IOException e) { e.printStackTrace(); } 
			catch (InvalidKeySpecException e) { e.printStackTrace(); } 
			catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		}
		return SERVER_PRIVATE_KEY;
	}
}
