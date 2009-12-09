package utils.kserver;

import java.security.interfaces.RSAPublicKey;

import utils.Password;

/**
 * Structure used by key server to store user data.
 */
public class UserKeyData 
{	
	protected Password password;
	public byte[] getSalt() { return password.salt; }
	public byte[] getPwdHash() { return password.pwd2Hash; }
	
	protected byte[] publicKey;
	public byte[] getPublicKey() { return publicKey; }
	
	protected byte[] encryptedPrivateKeyBytes;
	public byte[] getPrivKeyBytes() { return encryptedPrivateKeyBytes; }
	
	public UserKeyData(byte[] salt, byte[] pwd2Hash, RSAPublicKey key, byte[] encrPrivKeyBytes)
	{
		this(salt, pwd2Hash, key.getEncoded(), encrPrivKeyBytes);
	}
	
	public UserKeyData(byte[] salt, byte[] pwd2Hash, byte[] rsaKey, byte[] encrPrivKeyBytes)
	{
		this.password = new Password(pwd2Hash, salt);
		this.publicKey = rsaKey;
		this.encryptedPrivateKeyBytes = encrPrivKeyBytes;
	}
}
