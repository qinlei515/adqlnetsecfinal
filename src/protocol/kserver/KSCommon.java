package protocol.kserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.ArrayList;

import protocol.client.Common;

import utils.BufferUtils;
import utils.Constants;

public class KSCommon 
{
	private static MessageDigest md = utils.Constants.challengeHash();
	
	//TODO: Redo this as UDP instead of TCP
	public static boolean provideChallenge1(Socket client) throws IOException
	{
		DataOutputStream toClient = new DataOutputStream(client.getOutputStream());
		DataInputStream fromClient = new DataInputStream(client.getInputStream());
		{
			byte[] challenge1 = calculateChallenge1(client);
			toClient.write(challenge1);
		}
		byte[] response1 = Common.getResponseComponent(fromClient);
		return BufferUtils.equals(response1, calculateChallenge1(client));
	}
	
	protected static byte[] calculateChallenge1(Socket client)
	{
		byte[] cAddr = client.getInetAddress().getAddress();
		md.reset();
		md.update(BufferUtils.concat(cAddr, utils.kserver.KSConstants.C_1_SECRET));
		return md.digest();
	}
	
	public static ArrayList<byte[]> createChallenge2(byte[] number)
	{
		ArrayList<byte[]> answer = new ArrayList<byte[]>();
		answer.add(Constants.challengeHash().digest(number));
		byte[] maskedNumber = new byte[number.length];
		for(int i = number.length/2; i < number.length; i++)
			maskedNumber[i] = 0;
		answer.add(maskedNumber);
		return answer;
	}
}
