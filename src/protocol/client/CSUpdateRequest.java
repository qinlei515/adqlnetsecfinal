package protocol.client;

import java.net.Socket;

import protocol.Protocol;
import utils.CipherPair;
import utils.Connection;

public class CSUpdateRequest implements Protocol {

	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	public boolean run(Socket connection, CipherPair sessionCipher) {
		// TODO Auto-generated method stub
		return false;
	}

}
