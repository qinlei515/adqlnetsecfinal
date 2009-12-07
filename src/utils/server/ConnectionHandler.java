package utils.server;

import java.io.IOException;
import java.net.Socket;

import javax.crypto.SecretKey;

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
		SecretKey sessionKey = server.authenticate(connection);
		if(sessionKey != null) server.getBehavior().handleConnection(sessionKey, connection);
		try { connection.close(); } 
		catch (IOException e) { e.printStackTrace(); }
	}
}
