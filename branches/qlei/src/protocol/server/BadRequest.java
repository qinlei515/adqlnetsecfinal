package protocol.server;

import java.io.IOException;
import java.net.Socket;

import protocol.Protocol;
import utils.CipherPair;
import utils.Connection;

public class BadRequest implements Protocol 
{
	
	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket connection, CipherPair sessionCipher) 
	{
		//TODO: Let the client know before closing the connection.
		try { connection.close(); } 
		catch (IOException e) { e.printStackTrace(); }
		return false;
	}

}
