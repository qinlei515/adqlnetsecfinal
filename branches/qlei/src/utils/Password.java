package utils;


/** 
 * A simple structure for storing all information necessary to use a salted password.
 */
public class Password 
{
	public byte[] pwd2Hash;
	public byte[] salt;
	
	public Password() {}
	
	public Password(byte[] pwd2Hash, byte[] salt)
	{
		this.pwd2Hash = pwd2Hash;
		this.salt = salt;
	}
}
