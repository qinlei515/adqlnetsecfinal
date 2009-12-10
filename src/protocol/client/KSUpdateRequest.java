package protocol.client;

import java.net.Socket;

import protocol.Protocol;
import utils.CipherPair;
import utils.Connection;

/**
 * Unimplemented. Protocol for updating a user's information on the key server.
 * 
 * @author Alex Dubreuil
 *
 */
public class KSUpdateRequest implements Protocol 
{

	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket connection, CipherPair sessionCipher) 
	{
		// TODO Auto-generated method stub
		return false;
	}

}
