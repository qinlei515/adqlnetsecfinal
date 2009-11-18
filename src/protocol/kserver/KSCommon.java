package protocol.kserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.MessageDigest;

import utils.BufferUtils;

public class KSCommon 
{
	private static MessageDigest md = utils.Constants.challengeHash();
	
	public static boolean provideChallenge1(Socket client) throws IOException
	{
		DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
		DataInputStream fromClient = new DataInputStream(client.getInputStream());
		{
			byte[] challenge1 = calculateChallenge1(client);
			toClient.write(challenge1);
		}
		byte[] response1 = getResponse(fromClient);
		return BufferUtils.equals(response1, calculateChallenge1(client));
	}
	
	protected static byte[] calculateChallenge1(Socket client)
	{
		byte[] cAddr = client.getInetAddress().getAddress();
		md.reset();
		md.update(utils.BufferUtils.concat(cAddr, utils.kserver.KSConstants.C_1_SECRET));
		return md.digest();
	}
	
	public static byte[] getResponse(DataInputStream fromClient) throws IOException
	{
		int responseSize = fromClient.read() * 256 + fromClient.read();
		byte[] response = new byte[responseSize];
		fromClient.read(response);
		return response;
	}
}
