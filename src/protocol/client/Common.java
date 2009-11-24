package protocol.client;

import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import utils.BufferUtils;
import utils.Constants;
import utils.ServerEncryption;

public class Common 
{
	
	// Challenge 1: Prove we're here.
	public static byte[] handleChallenge1(DataInputStream fromServer) throws IOException
	{
		return getResponse(fromServer);
	}
	
	// Challenge 2: Guess-the-number
	public static byte[] handleChallenge2(DataInputStream fromServer) throws NoSuchAlgorithmException, IOException
	{
		byte[] resp2 = getResponse(fromServer);
		byte[] hash = new byte[utils.Constants.C_HASH_SIZE];
		BufferUtils.copy(resp2, hash, hash.length);
		int sizeOfR = resp2[hash.length];
		byte[] number = new byte[sizeOfR];
		BufferUtils.copy(resp2, number, sizeOfR, hash.length+1, 0);
		Common.guessTheNumber(hash, number);
		return number;
	}
	
	public static byte[] getResponse(DataInputStream fromServer) throws IOException
	{
		int responseSize = BufferUtils.translate(fromServer.read(), fromServer.read());
		byte[] response = new byte[responseSize];
		fromServer.read(response);
		return response;
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
	
	public static SecretKey authenticateServerResponse(byte[] response, KeyPair ourKey)
	{
		int respIndex = 0;
		// First bytes are the signed hash of the DH key
		byte[] signedDHKeyHash = new byte[Constants.RSA_BLOCK_SIZE];
		BufferUtils.copy(response, 
				signedDHKeyHash, 
				Constants.RSA_BLOCK_SIZE);
		respIndex += Constants.RSA_BLOCK_SIZE;
		// Next two bytes is the size of the DH key
		int dhBytes = response[respIndex] * 256;
		respIndex++;
		dhBytes += response[respIndex];
		respIndex++;
		// Get the dhKey
		byte[] dhKeyBytes = new byte[dhBytes];
		BufferUtils.copy(response, dhKeyBytes, dhBytes, respIndex, 0);
		respIndex += dhBytes;
		// Remainder of the message is the authentication.
		byte[] auth = new byte[response.length - respIndex];
		
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
	        KeyFactory keyFact;
			
			keyFact = KeyFactory.getInstance("DH");
			PublicKey serverDHKey = keyFact.generatePublic(x509KeySpec);
			
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(ourKey.getPrivate());
			ka.doPhase(serverDHKey, true);
			
			SecretKey sessionKey = ka.generateSecret(Constants.SESSION_KEY_ALG);
			Cipher authCipher = Cipher.getInstance(Constants.SESSION_KEY_ALG);
			authCipher.init(Cipher.DECRYPT_MODE, sessionKey);
			byte[] authCheck = authCipher.doFinal(auth);
			byte[] ourKeyBytes = ourKey.getPublic().getEncoded();
			byte[] ourAuthKeyBytes = new byte[ourKeyBytes.length];
			BufferUtils.copy(authCheck, ourAuthKeyBytes, ourKeyBytes.length);
			if(!BufferUtils.equals(ourKeyBytes, ourAuthKeyBytes))
			{
				System.err.println("Server authentication response did not match our key.");
				return null;
			}
			Calendar cal = Calendar.getInstance();
			int dateSize = Constants.DATE_FORMAT.format(cal.getTime()).getBytes().length;
			long ourTime = cal.getTime().getTime();
			byte[] serverTimestampBytes = new byte[dateSize];
			BufferUtils.copy(auth, serverTimestampBytes, 
					serverTimestampBytes.length, 
					ourKeyBytes.length, 0);
			String serverTimestamp = new String(serverTimestampBytes);
			long serverTime = Constants.DATE_FORMAT.parse(serverTimestamp).getTime();
			// Check that the times are close
			if(Math.abs(ourTime - serverTime) > Constants.MAX_TIMESTAMP_ERROR_MILLIS)
			{
				System.err.println("Server timestamp does not match.");
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
		// Server timestamp failed to parse.
		catch (ParseException e) { System.err.println("Server timestamp failed to parse: " 
				+ e.getMessage()); }
		return null;
	}
}
