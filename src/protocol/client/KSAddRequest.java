package protocol.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.spec.DHParameterSpec;


import utils.BufferUtils;

public class KSAddRequest 
{
	public final byte[] request = "USER_ADD".getBytes();
	public final int DEFAULT_BUFFER = 512;
//	public enum STATE{NEW, REQUEST, CHALLENGE1, CHALLENGE2, ESTABLISHED, DONE};
	Socket kserver;
//	STATE state;
	
	public KSAddRequest(Socket ks) { this.kserver = ks; }
	
	public boolean doRequest(DHParameterSpec ourSpecs)
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(kserver.getOutputStream());
			DataInputStream fromServer = new DataInputStream(kserver.getInputStream());
			BufferedReader stringFromServer = new BufferedReader(new InputStreamReader(kserver.getInputStream()));
			KeyPairGenerator dhgen = KeyPairGenerator.getInstance("DH");
			dhgen.initialize(ourSpecs);
			KeyPair kpair = dhgen.generateKeyPair();
			PublicKey pubKey = kpair.getPublic();
			
			byte[] encodedKey = pubKey.getEncoded();
			//TODO: Add hash of server's public key for identification to req1
			byte[] req1 = new byte[request.length + encodedKey.length];
			for(int i = 0; i < request.length; i++)
				req1[i] = request[i];
			for(int i = 0; i < encodedKey.length; i++)
				req1[i+request.length] = encodedKey[i];
			toServer.write(req1);
			// TODO: For simplicity, we assume we will receive two challenge from the server.
			toServer.write(Common.handleChallenge1(fromServer));
			toServer.write(Common.handleChallenge2(fromServer));
			// Challenges are done. Resend original request.
			toServer.write(req1);
			String messageType = stringFromServer.readLine();
			if(messageType.equals(utils.Constants.SERVER_KEY_RESET))
			{
				//TODO: Update the server's primary and secondary public keys.
				//And resend the request yet again.
			}			
			byte[] signedDHKey = Common.getResponse(fromServer);
			byte[] auth = Common.getResponse(fromServer);
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		// This catch should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		// Return false if we escape the try.
		return false;
	}
	
	
}
