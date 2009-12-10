package protocol.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.Mac;

import cclient.ClientUser;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.Constants;

public class KSPublicRequest implements Protocol {
	
	ClientUser user;
	/* name of correspondent */
	String ctname;
	
	public KSPublicRequest(ClientUser user, String ctname)
	{
		this.user = user;
		this.ctname = ctname;
	}
	
	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket server, CipherPair sessionCipher) {
		try 
		{
			DataOutputStream toServer = new DataOutputStream(server.getOutputStream());
			DataInputStream fromServer = new DataInputStream(server.getInputStream());
			
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			sessionCipher.initEncrypt();
			
			{
				byte[] message = Common.createMessage(Requests.PUBLIC, ctname.getBytes());
				byte[] iv = sessionCipher.encrypt.getIV();
				toServer.write(Common.wrapMessage(message, iv, hmac, sessionCipher));
			}
			{
				ArrayList<byte[]> resp = Common.getResponse(fromServer);
				byte[] message = Common.checkIntegrity(resp, hmac, sessionCipher);
				if(message == null)
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				resp = Common.splitResponse(message);
				byte[] exists = resp.get(0);
				if(BufferUtils.equals(exists, Requests.DENY))
				{
					System.err.println("Could not retrieve " + ctname + "'s public key.");
					return false;
				}	
				byte[] PublicKeyBytes = resp.get(1);
				byte[] skhash = resp.get(2);
				MessageDigest md = MessageDigest.getInstance(Constants.DH_HASH_ALG);
				byte[] skhashc =  md.digest(sessionCipher.key.getEncoded());
				if(!BufferUtils.equals(skhashc, skhash))
				{
					System.err.println("Integrity check failed.");
					return false;
				}
				KeyFactory kFactory = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(PublicKeyBytes);
				RSAPublicKey publicKey = (RSAPublicKey)kFactory.generatePublic(keySpec);
				user.AddPubKey(ctname, publicKey);
				System.out.println("Successfully retrieved public key.");
				return true;
			}
		}
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); } 
		catch (IOException e) { e.printStackTrace(); }
		catch (InvalidKeySpecException e) { e.printStackTrace(); }
		return false;
	}

}
