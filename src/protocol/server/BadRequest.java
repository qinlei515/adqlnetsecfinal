package protocol.server;

import java.net.Socket;

import javax.crypto.Cipher;

import protocol.Protocol;

public class BadRequest implements Protocol 
{
	
	public boolean run(Socket connection, Cipher sessionCipher) 
	{
		//TODO: Let the client know, close the connection.
		return false;
	}

}
