package utils.kserver;

import java.net.Socket;

import javax.crypto.SecretKey;

import utils.server.ServerBehavior;

public class KServerBehavior implements ServerBehavior 
{

	public void handleConnection(SecretKey sessionKey, Socket connection) 
	{
		// TODO: Implement the actual key server functionality here.
	}

}
