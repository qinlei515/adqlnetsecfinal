package utils.server;

import java.io.IOException;
import java.net.Socket;

import utils.CipherPair;

public class ConnectionHandler implements Runnable
{
	
	protected Socket connection;
	protected Server server;
	protected ServerBehavior behavior;
	
	public ConnectionHandler(Socket connection, Server s)
	{
		this.connection = connection;
		this.server = s;
	}

	public void run() 
	{
		CipherPair sessionCipher = server.authenticate(connection);
		if(sessionCipher != null) server.getBehavior().handleConnection(sessionCipher, connection);
		try { connection.close(); } 
		catch (IOException e) { e.printStackTrace(); }
	}
}
