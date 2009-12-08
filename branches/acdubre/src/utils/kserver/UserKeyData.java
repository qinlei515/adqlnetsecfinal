package utils.kserver;

import java.security.interfaces.RSAPublicKey;

/**
 * Structure used by key server to store user data.
 */
public class UserKeyData 
{
	protected byte[] pwdSalt;
	public byte[] getSalt() { return pwdSalt; }
	
	protected byte[] pwd2Hash;
	public byte[] getPwdHash() { return pwd2Hash; }
	
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
		this.pwdSalt = salt;
		this.pwd2Hash = pwd2Hash;
		this.publicKey = rsaKey;
		this.encryptedPrivateKeyBytes = encrPrivKeyBytes;
	}
}
