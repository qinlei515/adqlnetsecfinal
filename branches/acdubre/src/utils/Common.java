package utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;

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
		return createMessage(number);
	}

	protected static byte[] getResponseComponent(DataInputStream from) throws IOException
	{
		int responseSize = BufferUtils.translate(from.read(), from.read());
		byte[] response = new byte[responseSize];
		from.read(response);
		return response;
	}

	public static ArrayList<byte[]> getResponse(DataInputStream from) throws IOException
	{
		int numComponents = BufferUtils.translate(from.read(), from.read());
		if(numComponents == 65535)
		{
			System.err.println("Read -1 -1, connection closed at other end.");
			return new ArrayList<byte[]>();
		}
		ArrayList<byte[]> answer = new ArrayList<byte[]>();
		for(int i = 0; i < numComponents; i++)
		{
			answer.add(getResponseComponent(from));
		}
		return answer;
	}

	public static ArrayList<byte[]> splitResponse(byte[] resp)
	{
		int numComponents = BufferUtils.translate(resp[0], resp[1]);
		ArrayList<byte[]> answer = new ArrayList<byte[]>();
		int pos = 2;
		for(int i = 0; i < numComponents; i++)
		{
			byte[] next = new byte[BufferUtils.translate(resp[pos], resp[pos+1])];
			pos += 2;
			BufferUtils.copy(resp, next, next.length, pos, 0);
			pos += next.length;
			answer.add(next);
		}
		return answer;
	}

	public static byte[] createMessage(byte[]... components)
	{
		int messageLength = 0;
		for(int i = 0; i < components.length; i++)
			messageLength += (components[i].length + 2);

		byte[] answer = new byte[messageLength+2];

		// Start with the length of the message
		BufferUtils.copy(BufferUtils.translate(components.length), answer, 2);

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
		int messageLength = 0;
		for(int i = 0; i < components.size(); i++)
			messageLength += (components.get(i).length + 2);

		byte[] answer = new byte[messageLength+2];

		// Start with the length of the message
		BufferUtils.copy(BufferUtils.translate(components.size()), answer, 2);

		int pos = 2;
		for(int i = 0; i < components.size(); i++)
		{
			// Start each component with the length of that component
			BufferUtils.copy(BufferUtils.translate(components.get(i).length), answer, 2, 0, pos);
			pos += 2;
			// Add the component itself
			BufferUtils.copy(components.get(i), answer, components.get(i).length, 0, pos);
			pos += components.get(i).length;
		}
		return answer;
	}

	public static void guessTheNumber(byte[] hash, byte[] given) throws NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance(Constants.CHALLENGE_HASH_ALG);
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
	public static void plusOne(byte[] number)
	{
		int i = 0;
		while(number[i] == Byte.MAX_VALUE)
		{
			number[i] = 0;
			i++;
		}
		number[i]++;
	}

	public static byte[] sign(byte[] toSign, RSAPrivateKey key)
	{
		try
        {
    		Signature sig = Signature.getInstance(Constants.SIGNATURE_ALG);
    		sig.initSign(key);
    		sig.update(toSign);
    		return sig.sign();
        }
        // Should be unreachable.
        catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
        catch (SignatureException e) { e.printStackTrace(); } 
        catch (InvalidKeyException e) { e.printStackTrace(); } 
        return null;
	}
	
	public static boolean verify(byte[] signed, byte[] message, RSAPublicKey key)
	{
		try
		{
			Signature sig = Signature.getInstance(Constants.SIGNATURE_ALG);
			sig.initVerify(key);
			sig.update(message);
			return sig.verify(signed);
		}
		// Should be unreachable.
		catch(NoSuchAlgorithmException e) { e.printStackTrace(); }
		//TODO: Handle corrupted etc. key files.
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (SignatureException e) { e.printStackTrace(); } 
		return false;
	}

	public static byte[] wrapMessage(byte[] message, Mac hmac, CipherPair sessionCipher)
	{
		try 
		{
			byte[] encrMessage = sessionCipher.encrypt.doFinal(message);
			byte[] mac = hmac.doFinal(message);
			return createMessage(encrMessage, mac);
		}
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); }
		return null;
	}

	public static byte[] wrapMessage(byte[] message, byte[] iv, Mac hmac, CipherPair sessionCipher)
	{
		try 
		{
			byte[] encrMessage = sessionCipher.encrypt.doFinal(message);
			byte[] mac = hmac.doFinal(message);
			return createMessage(iv, encrMessage, mac);
		}
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); }
		return null;
	}

	/**
	 * Does mac match the decrypted message?
	 * 
	 * @param encrMessage The message to be decrypted and integrity checked.
	 * @param mac The MAC for message.
	 * @param hmac The hmac function, initialized.
	 * @param sessionCipher The cipher to decrypt the message.
	 * @return The message if the MAC matches, else null.
	 */
	public static byte[] checkIntegrity(byte[] encrMessage, byte[] mac, Mac hmac, CipherPair sessionCipher)
	{
		try 
		{ 
			byte[] answer = sessionCipher.decrypt.doFinal(encrMessage);
			byte[] checkMac = hmac.doFinal(answer);
			if(BufferUtils.equals(mac, checkMac))
				return answer;
		} 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); }
		return null;
	}

	public static byte[] checkIntegrity(ArrayList<byte[]> resp, Mac hmac, CipherPair sessionCipher)
	{
		return checkIntegrity(resp.get(0), resp.get(1), hmac, sessionCipher);
	}
}
