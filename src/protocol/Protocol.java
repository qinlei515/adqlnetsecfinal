package protocol;

import java.net.Socket;

import utils.CipherPair;

public interface Protocol 
{
	/**
	 * Handle a specific type of request.
	 * 
	 * @param connection The connection over which the conversation takes place.
	 * @param sessionCipher The cipher being used.
	 * @return Whether the request completed successfully.
	 */
	public boolean run(Socket connection, CipherPair sessionCipher);
}
