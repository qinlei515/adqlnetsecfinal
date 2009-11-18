package protocol.client;

import java.io.DataInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import utils.BufferUtils;

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
		int responseSize = fromServer.read() * 256 + fromServer.read();
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
