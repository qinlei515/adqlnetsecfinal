package utils.constants;

/**
 * Algorithms, Modes, Key sizes
 */
public class CipherInfo 
{
	public static final String SESSION_KEY_ALG = "AES";
	public static final String SESSION_KEY_MODE = "/CBC/ISO10126Padding";
	
	public static final String SIGNATURE_ALG = "SHA1withRSA";
	public static final String HMAC_SHA1_ALG = "HmacSHA1";
	
	public static final String CHALLENGE_HASH_ALG = "SHA1";
	public static final String PWD_HASH_ALGORITHM = "SHA1";
	public static final String DH_HASH_ALG = "SHA1";
	
	public static final int SESSION_KEY_SIZE = 128;
	public static final int RSA_KEY_SIZE = 1024;
}
