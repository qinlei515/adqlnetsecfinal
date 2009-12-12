package utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Stores a pair of linked CBC mode Ciphers and their key. 
 * Used in two-way communication - each side stores their 
 * encrypt algorithm, matched by the other side's decrypt algorithm, 
 * and vice versa.
 *
 */
public class CipherPair 
{
	private String algAndMode;
	
	// Got tired of writing getters and setters around here for simple structures.
	public SecretKey key;
	
	public Cipher encrypt;
	public Cipher decrypt;
	
	public CipherPair(String algAndMode, SecretKey key)
	{
		this.algAndMode = algAndMode;
		this.key = key;
	}
	
	/**
	 * Initialize the encrypt cipher for this side.
	 */
	public void initEncrypt()
	{
		try 
		{
			encrypt = Cipher.getInstance(algAndMode);
			encrypt.init(Cipher.ENCRYPT_MODE, key);
		} 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (NoSuchPaddingException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); }
	}
	
	/**
	 * Upon receiving an iv from the other side, initialize the decrypt Cipher.
	 * 
	 */
	public void initDecrypt(byte[] iv)
	{
		try
		{
			decrypt = Cipher.getInstance(algAndMode);
			decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		}
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (NoSuchPaddingException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
	}
}
