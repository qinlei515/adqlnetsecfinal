package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import cclient.ClientUser;

import protocol.Protocol;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.Constants;

public class ConnectionAccept implements Protocol 
{
	ClientUser user;
	
	public ConnectionAccept(ClientUser user)
	{
		this.user = user;
	}
	
	public boolean run(Connection c) 
	{
		try 
		{
			DataOutputStream toSrc = new DataOutputStream(c.s.getOutputStream());
			DataInputStream fromSrc = new DataInputStream(c.s.getInputStream());
			
			KeyPair kPair;
			PublicKey theirDHKey;
			RSAPublicKey srcKey;
			
			{
				ArrayList<byte[]> request = Common.getResponse(fromSrc);
				request = user.unwrapClientAuthMessage(request);
				byte[] name = request.get(0);
				byte[] dhPubKey = request.get(1);
				byte[] signed = request.get(2);
				srcKey = user.getPublicKey(BufferUtils.translateString(name));
				if(!Common.verify(signed, dhPubKey, srcKey))
				{
					System.out.println("Authentication failed.");
					return false;
				}
				
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dhPubKey);
		        KeyFactory keyFact = KeyFactory.getInstance("DH");
		        theirDHKey = keyFact.generatePublic(x509KeySpec);
				
				KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
				dhGen.initialize(Constants.getDHParameters());
				
				kPair = dhGen.generateKeyPair();
				PublicKey ourDHKey = kPair.getPublic();
				
				toSrc.write(user.authenticateToClient(ourDHKey, srcKey));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromSrc);
				c.cipher = user.authenticateResponse(resp, kPair, srcKey);
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		return false;
	}

}
