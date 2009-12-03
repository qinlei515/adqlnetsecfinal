package protocol.client;

import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import utils.BufferUtils;
import utils.Constants;
import utils.ServerEncryption;

public class Common 
{
	
	// Challenge 1: Prove we're here.
	public static byte[] handleChallenge1(DataInputStream fromServer) throws IOException
	{
		return getResponseComponent(fromServer);
	}
	
	// Challenge 2: Guess-the-number
	public static byte[] handleChallenge2(DataInputStream fromServer) throws NoSuchAlgorithmException, IOException
	{
		ArrayList<byte[]> resp = getResponse(fromServer);
		byte[] number = new byte[resp.get(1).length];
		BufferUtils.copy(resp.get(1), number, number.length);
		Common.guessTheNumber(resp.get(0), number);
		return number;
	}
	
	public static byte[] getResponseComponent(DataInputStream from) throws IOException
	{
		int responseSize = BufferUtils.translate(from.read(), from.read());
		byte[] response = new byte[responseSize];
		from.read(response);
		return response;
	}
	
	public static ArrayList<byte[]> getResponse(DataInputStream from) throws IOException
	{
		int numComponents = BufferUtils.translate(from.read(), from.read());
		ArrayList<byte[]> answer = new ArrayList<byte[]>();
		for(int i = 0; i < numComponents; i++)
			answer.add(getResponseComponent(from));
		return answer;
	}
	
	public static byte[] createMessage(byte[]... components)
	{
		int messageLength = 0;
		for(int i = 0; i < components.length; i++)
			messageLength += (components[i].length + 2);
		byte[] answer = new byte[messageLength+2];
		
		// Start with the length of the message
		BufferUtils.copy(BufferUtils.translate(messageLength), answer, 2);
		
		int pos = 2;
		for(int i = 0; i < components.length; i++)
		{
			// Start each component with the length of that component
			BufferUtils.copy(BufferUtils.translate(components[i].length), answer, 2, 0, pos);
			pos += 2;
			// Add the component itself
			BufferUtils.copy(components[i], answer, components[i].length, 0, pos);
			pos += components[i].length;
		}
		return answer;
	}
	
	public static byte[] createMessage(ArrayList<byte[]> components)
	{
		return createMessage((byte[][])components.toArray());
	}
	
	public static void guessTheNumber(byte[] hash, byte[] given) throws NoSuchAlgorithmException
	{
		MessageDigest md = utils.Constants.challengeHash();		
		md.update(given);
		byte[] ourHash = md.digest();
		boolean done = BufferUtils.equals(hash, ourHash);
		while(!done)
		{
			plusOne(given);
			md.update(given);
			ourHash = md.digest();
			done = BufferUtils.equals(hash, ourHash);
		}
	}
	
	// Interpret number as an integer; add one to it.
	protected static void plusOne(byte[] number)
	{
		int i = 0;
		while(number[i] == Byte.MAX_VALUE)
		{
			number[i] = 0;
			i++;
		}
		number[i]++;
	}
	
	public static SecretKey authenticateServerResponse(ArrayList<byte[]> response, KeyPair ourKey)
	{
		byte[] signedDHKeyHash = response.get(0);
		byte[] dhKeyBytes = response.get(1);
		byte[] iv = response.get(2);
		byte[] auth = response.get(3);
		
		// Authenticate the message.
		// Check the signature.
		byte[] unsignedHash = 
			ServerEncryption.unsign(signedDHKeyHash);
		byte[] checkHash = Constants.dhHash().digest(dhKeyBytes);

		if(!BufferUtils.equals(unsignedHash, checkHash))
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
			
			SecretKey sessionKey = ka.generateSecret(Constants.SESSION_KEY_ALG);
			Cipher authCipher = Cipher.getInstance(Constants.SESSION_KEY_ALG);
			authCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
			byte[] authCheck = authCipher.doFinal(auth);
			byte[] ourKeyBytes = ourKey.getPublic().getEncoded();
			if(!BufferUtils.equals(ourKeyBytes, authCheck))
			{
				System.err.println("Server authentication response did not match our key.");
				return null;
			}
			return sessionKey;
		} 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeySpecException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (NoSuchPaddingException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); } 
		return null;
	}
}
