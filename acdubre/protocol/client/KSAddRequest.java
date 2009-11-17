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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.spec.DHParameterSpec;

import protocol.Common;

import utils.BufferUtils;

public class KSAddRequest 
{
	public final byte[] request = "USER_ADD".getBytes();
	public final int DEFAULT_BUFFER = 512;
//	public enum STATE{NEW, REQUEST, CHALLENGE1, CHALLENGE2, ESTABLISHED, DONE};
	Socket kserver;
//	STATE state;
	
	public KSAddRequest(Socket ks) { this.kserver = ks; }
	
	public boolean doRequest(DHParameterSpec specs)
	{
		try 
		{
			DataOutputStream toServer = new DataOutputStream(kserver.getOutputStream());
			DataInputStream fromServer = new DataInputStream(kserver.getInputStream());
			KeyPairGenerator dhgen = KeyPairGenerator.getInstance("DH");
			dhgen.initialize(specs);
			KeyPair kpair = dhgen.generateKeyPair();
			PublicKey pubKey = kpair.getPublic();
			
			byte[] encodedKey = pubKey.getEncoded();
			byte[] req1 = new byte[request.length + encodedKey.length];
			for(int i = 0; i < request.length; i++)
				req1[i] = request[i];
			for(int i = 0; i < encodedKey.length; i++)
				req1[i+request.length] = encodedKey[i];
			toServer.write(req1);
			// TODO: For simplicity, we assume we will receive two challenge from the server.
			// Challenge 1: Prove we're here.
			{
				byte[] resp1 = getResponse(fromServer);
				toServer.write(resp1);
			}
			// Challenge 2: Guess-the-number
			{
				byte[] resp2 = getResponse(fromServer);
				byte[] hash = new byte[utils.Constants.C_HASH_SIZE];
				BufferUtils.copy(resp2, hash, hash.length);
				int sizeOfR = resp2[hash.length];
				byte[] number = new byte[sizeOfR];
				BufferUtils.copy(resp2, number, sizeOfR, hash.length+1);
				Common.guessTheNumber(hash, number);
				toServer.write(number);
			}
			// Challenges are done. Resend original request.
			toServer.write(req1);
		} 
		catch (IOException e) { e.printStackTrace(); } 
		catch (InvalidAlgorithmParameterException e) { e.printStackTrace(); }
		// This catch should be unreachable.
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		// Return false if we escape the try.
		return false;
	}
	
	protected byte[] getResponse(DataInputStream fromServer) throws IOException
	{
		byte[] response = new byte[DEFAULT_BUFFER];
		int bytesRead = 0;
		boolean active = true;
		while(active)
		{
			if(bytesRead == response.length)
			{
				byte[] tempResponse = new byte[response.length];
				BufferUtils.copy(response, tempResponse, response.length);
				response = new byte[response.length * 2];
				BufferUtils.copy(tempResponse, response, tempResponse.length);
			}
			fromServer.read(response, bytesRead, 1);
			bytesRead++;
			if(response[bytesRead-1] == 0 
					&& response[bytesRead-2] == 0 
					&& response[bytesRead-3] == 0)
				active = false;
		}
		return response;
	}
}
