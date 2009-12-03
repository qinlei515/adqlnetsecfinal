package protocol.kserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import protocol.client.Common;

import utils.BufferUtils;
import utils.Constants;
import utils.ServerEncryption;

public class Authenticate 
{
	
	public static SecretKey authenticate(DataOutputStream toClient, DataInputStream fromClient)
	{
		try 
		{
			ArrayList<byte[]> resp1 = Common.getResponse(fromClient);
			byte[] clientKeyBytes = resp1.get(0);
			if(!BufferUtils.equals(resp1.get(1), Constants.getServerKeyHash()))
			{
				//TODO: Run the key overwrite protocol.
			}
			
			// Send guess-the-number challenge
			byte[] challengeNumber = BufferUtils.random(Constants.CHALLENGE_BYTESIZE);
			toClient.write(Common.createMessage(KSCommon.createChallenge2(challengeNumber)));
			
			byte[] resp2 = Common.getResponseComponent(fromClient);
			if(!BufferUtils.equals(resp2, challengeNumber))
			{
				//TODO: Inform the client + Terminate the connection.
			}	
			
			// Set up the client's DH public key
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientKeyBytes);
	        KeyFactory keyFact = KeyFactory.getInstance("DH");
			PublicKey clientDHKey = keyFact.generatePublic(x509KeySpec);
			
			// Create the server's DH key
			// TODO: Reuse to decrease server load?
			KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
			dhGen.initialize(Constants.getDHParameters());
			
			KeyPair kPair = dhGen.generateKeyPair();
			
			// Set up the private key.
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(kPair.getPrivate());
			ka.doPhase(clientDHKey, true);
			
			SecretKey sessionKey = ka.generateSecret(Constants.SESSION_KEY_ALG);
			
			// Sign & send to client
			byte[] pubKeyBytes = kPair.getPublic().getEncoded();
			byte[] signedHash = ServerEncryption.sign(Constants.dhHash().digest(pubKeyBytes));
			
			Cipher authCipher = Constants.sessionCipher();
			authCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
			byte[] iv = authCipher.getIV();
			byte[] auth = authCipher.doFinal(clientKeyBytes);
			toClient.write(Common.createMessage(signedHash, pubKeyBytes, iv, auth));
			
			return sessionKey;
		}
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		catch (InvalidKeySpecException e) { e.printStackTrace(); }
		// Should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		// Return null if we escape the try
		return null;
	}
}
