package protocol.client;

import java.net.Socket;

import protocol.Protocol;
import utils.CipherPair;
import utils.Connection;

/**
 * Unimplemented. A protocol for updating a user's information on the chat server. 
 *
 */
public class CSUpdateRequest implements Protocol {

	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket connection, CipherPair sessionCipher) {
		// TODO Auto-generated method stub
		return false;
	}

}
