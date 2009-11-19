package utils;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

import junit.framework.TestCase;

public class TestServerEncryption extends TestCase
{
	final String testPrivateKeyFile = "tests/serverPrivate_test.key";
	RSAPrivateKey serverTestKey;
	DHParameterSpec dhSpec;
	PublicKey dhPubKey;
	byte[] signedDHKey;
	
	public void setUp() 
	{
		File keyFile = new File(testPrivateKeyFile);
		FileInputStream keyInFile;
		try 
		{
			keyInFile = new FileInputStream(keyFile);
			DataInputStream keyIn = new DataInputStream(keyInFile);
			byte[] keyBytes = new byte[(int)keyFile.length()];
			keyIn.read(keyBytes);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
			serverTestKey = (RSAPrivateKey)Constants.getRSAKeyFactory().generatePrivate(keySpec);
			
			AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
			paramGen.init(512);
			AlgorithmParameters params = paramGen.generateParameters();
			dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
			KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
			dhGen.initialize(dhSpec);
			KeyPair kPair = dhGen.generateKeyPair();
			dhPubKey = kPair.getPublic();
			byte[] dhKeyBytes = dhPubKey.getEncoded();
			
			Cipher signCipher = Cipher.getInstance("RSA");
			signCipher.init(Cipher.DECRYPT_MODE, serverTestKey);
			System.out.println(dhKeyBytes.length);
			signedDHKey = signCipher.doFinal(dhKeyBytes);
		} 
		catch (FileNotFoundException e) { e.printStackTrace(); } 
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidKeySpecException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidParameterSpecException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); } 
		catch (NoSuchPaddingException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); }
	}
	
	public void test_read_primary_key()
	{
		Constants.getServerPrimaryKey();
	}	
}
