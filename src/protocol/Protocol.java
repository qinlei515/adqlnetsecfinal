package protocol;

import utils.Connection;

public interface Protocol 
{
	/**
	 * Handle a specific type of request, Client to Server or vice versa.
	 * 
	 * @param connection The connection over which the conversation takes place.
	 * @param sessionCipher The cipher being used.
	 * @return Whether the request completed successfully.
	 */
	public boolean run(Connection c);
}
