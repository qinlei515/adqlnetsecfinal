package protocol.client;

import java.net.Socket;

import javax.crypto.Cipher;

import protocol.Protocol;


public class KSAddRequest implements Protocol
{
	public boolean run(Socket connection, Cipher sessionCipher) 
	{
		return false;
	}
	
}
