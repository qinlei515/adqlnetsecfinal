package utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;

import utils.constants.CipherInfo;
import utils.exceptions.ConnectionClosedException;

/**
 * A bunch of functionality common to servers and clients.
 * May still need some refactoring.
 * 
 * Some background:
 * 
 * We use a simple communication language. Each message starts with
 * a two-byte representation of the number of components in the message, followed
 * immediately by the first component.
 * 
 * Each component consists of a two-byte representation of the size of the component,
 * followed by the data of a component.
 * 
 * Sometimes we have multiple layers of message wrapping within a communication -
 * when using symmetric encryption, we typically turn the data into a message, 
 * encrypt that message, and use that as a component in a new message.
 * 
 * Interpreting a message is left entirely to the Protocol handling it.
 * 
 * @author Alex Dubreuil
 *
 */
public class Common 
{
	/**
	 * Read a single component from from.
	 */
	protected static byte[] getResponseComponent(DataInputStream from) throws IOException
	{
		int responseSize = BufferUtils.translate(from.read(), from.read());
		byte[] response = new byte[responseSize];
		from.read(response);
		return response;
	}

	/**
	 * Read an entire message from from.
	 * The message must follow the requirements outlined above or bad things happen.
	 * @throws ConnectionClosedException 
	 */
	public static ArrayList<byte[]> getResponse(DataInputStream from) throws IOException, ConnectionClosedException
	{
		int numComponents = BufferUtils.translate(from.read(), from.read());
		if(numComponents == 65535)
		{
			System.err.println("Read -1 -1, connection closed at other end.");
			throw new ConnectionClosedException();
		}
		ArrayList<byte[]> answer = new ArrayList<byte[]>();
		for(int i = 0; i < numComponents; i++)
		{
			answer.add(getResponseComponent(from));
		}
		return answer;
	}

	/**
	 * This functionality is built in to getResponse, but is necessary to split
	 * encrypted message components after decrypting them.
	 */
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

	/**
	 * Turn the given components into a message meeting the requirements outlined above.
	 */
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

	/**
	 * Sign toSign using key.
	 */
	public static byte[] sign(byte[] toSign, RSAPrivateKey key)
	{
		try
        {
    		Signature sig = Signature.getInstance(CipherInfo.SIGNATURE_ALG);
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
	
	/**
	 * Verify that signed matches [message]key
	 */
	public static boolean verify(byte[] signed, byte[] message, RSAPublicKey key)
	{
		try
		{
			Signature sig = Signature.getInstance(CipherInfo.SIGNATURE_ALG);
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

	/**
	 * Encrypt the given message with sessionCipher.encrypt.
	 * Create a MAC for message.
	 * 
	 * @return A message (as defined above) containing the encrypted message and the MAC.
	 */
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

	/**
	 * Encrypt the given message with sessionCipher.encrypt
	 * Create a MAC for the message.
	 * 
	 * @return A message (as defined above) containing iv, the encrypted message and the MAC.
	 */
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

	/**
	 * Does mac ( = resp.get(0) ) match the decrypted message?
	 * 
	 * (Encrypted message = resp.get(1))
	 * 
	 */
	public static byte[] checkIntegrity(ArrayList<byte[]> resp, Mac hmac, CipherPair sessionCipher)
	{
		if(resp.size() == 2)
			return checkIntegrity(resp.get(0), resp.get(1), hmac, sessionCipher);
		else
			return null;
	}
}
