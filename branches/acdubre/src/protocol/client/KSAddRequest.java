package protocol.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import utils.*;

public class KSAddRequest 
{
	Socket kserver;
	
	byte[] request;
	
	public KSAddRequest(Socket kserver, String userName, byte[] hash2Password, PublicKey pubKey, byte[] encryptedPrivateKey) 
	{ 
		this.kserver = kserver;
		byte[] userNameBytes = userName.getBytes();
		byte[] uNLength = BufferUtils.translate(userNameBytes.length);
		byte[] pubKeyBytes = pubKey.getEncoded();
		byte[] pubKLength = BufferUtils.translate(pubKeyBytes.length);
		byte[] privKLength = BufferUtils.translate(encryptedPrivateKey.length);
		
		this.request = BufferUtils.concat(uNLength, userName.getBytes(),
				hash2Password,
				pubKLength, pubKeyBytes,
				privKLength, encryptedPrivateKey);
	}
	
	public boolean doRequest(DHParameterSpec ourSpecs)
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(kserver.getOutputStream());
			DataInputStream fromServer = new DataInputStream(kserver.getInputStream());

			SecretKey sessionKey = KSAuthenticate.authenticate(toServer, fromServer, ourSpecs);
			Cipher c = Constants.sessionCipher();
			c.init(Cipher.ENCRYPT_MODE, sessionKey);
			byte[] iv = c.getIV();
			byte[] encryptedResponse = c.doFinal(request);
			byte[] respLength = BufferUtils.translate(iv.length + encryptedResponse.length);
			toServer.write(BufferUtils.concat(respLength, iv, encryptedResponse));
			
		} 
		catch (IOException e) { e.printStackTrace(); } 
		// These catches should be unreachable.
		catch (InvalidKeyException e) { e.printStackTrace(); }
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		// Return false if we escape the try.
		return false;
	}
	
	
}
