package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import utils.BufferUtils;
import utils.Constants;

public class KSAuthenticate 
{

	//TODO: Grab the DHParameterSpec from a file instead.
	//TODO: Generate a DHParameterSpec file.
	public static SecretKey authenticate(DataOutputStream toServer, DataInputStream fromServer)
	{
		try 
		{
			KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
			dhGen.initialize(Constants.getDHParameters());
			KeyPair kPair = dhGen.generateKeyPair();
			PublicKey pubKey = kPair.getPublic();
		
			toServer.write(Common.createMessage(pubKey.getEncoded(), Constants.getServerKeyHash()));
			// TODO: For simplicity, we currently assume we will receive the challenge from the server.
			toServer.write(Common.handleChallenge2(fromServer));
			
			ArrayList<byte[]> resp = Common.getResponse(fromServer);
			if(BufferUtils.equals(resp.get(0), Constants.SERVER_KEY_RESET))
			{
				//TODO: Update the server's primary and secondary public keys.
			}			
			SecretKey sessionKey = Common.authenticateServerResponse(resp, kPair);
			return sessionKey;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		// Should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
		// Return null if we escape the try
		return null;
	}
}
