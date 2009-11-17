package protocol;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import utils.BufferUtils;

public class Common 
{
	public static void guessTheNumber(byte[] hash, byte[] given) throws NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance(utils.Constants.CHALLENGE_HASH);		
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
	private static void plusOne(byte[] number)
	{
		int i = 0;
		while(number[i] == Byte.MAX_VALUE)
		{
			number[i] = 0;
			i++;
		}
		number[i]++;
	}
}
