package utils.kserver;

import java.security.interfaces.RSAPublicKey;

/**
 * Structure used by key server to store user data.
 */
public class UserKeyData 
{
	protected byte[] pwdSalt;
	public byte[] getSalt() { return pwdSalt; }
	protected byte[] pwd3Hash;
	public byte[] getPwdHash() { return pwd3Hash; }
	protected RSAPublicKey publicKey;
	public RSAPublicKey getPublicKey() { return publicKey; }
	protected byte[] encryptedPrivateKeyBytes;
	public byte[] getPrivKeyBytes() { return encryptedPrivateKeyBytes; }
	
	public UserKeyData(byte[] salt, byte[] pwd3Hash, RSAPublicKey key, byte[] encrPrivKeyBytes)
	{
		this.pwdSalt = salt;
		this.pwd3Hash = pwd3Hash;
		this.publicKey = key;
		this.encryptedPrivateKeyBytes = encrPrivKeyBytes;
	}
}
