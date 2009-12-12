package protocol.server;

import java.net.Socket;

import protocol.Protocol;
import utils.CipherPair;
import utils.Connection;

/**
 * Unimplemented. Response to a CSUpdate request, modifies the user's information on the
 * chat server.
 *
 */
public class CSUpdate implements Protocol {

	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket connection, CipherPair sessionCipher) {
		// TODO Auto-generated method stub
		return false;
	}

}
