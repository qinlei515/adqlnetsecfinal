package utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Constants 
{
	public static final int CHAT_SERVER_PORT = 6417;
	public static final int KEY_SERVER_PORT = 6473;
	public static final int RSA_KEY_SIZE = 1024;
	
	public static final String CHALLENGE_HASH_ALG = "SHA1";
	private static MessageDigest CHALLENGE_HASH;
	
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
	
	public static final int C_HASH_SIZE = 40;

	public static final String SERVER_KEY_RESET = "SKRESET.";
}
