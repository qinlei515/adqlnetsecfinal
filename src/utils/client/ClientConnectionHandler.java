package utils.client;

import java.net.Socket;

import protocol.Protocol;
import utils.Connection;

/**
 * Simpler than the Server ConnectionHandler, each deals exclusively with a single protocol.
 */
public class ClientConnectionHandler implements Runnable
{
	protected Socket connection;
	protected Protocol p;
	
	public ClientConnectionHandler(Socket connection, Protocol p)
	{
		this.connection = connection;
		this.p = p;
	}
	
	public void run() 
	{
		p.run(new Connection(connection, null));
	}
	
}
