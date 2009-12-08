package utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class CipherPair 
{
	private String algAndMode;
	public SecretKey key;
	
	public Cipher encrypt;
	public Cipher decrypt;
	
	public CipherPair(String algAndMode, SecretKey key)
	{
		this.algAndMode = algAndMode;
		this.key = key;
	}
	
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
