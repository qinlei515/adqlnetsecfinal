package utils.server;

import java.net.Socket;

import javax.crypto.SecretKey;

public interface ServerBehavior 
{
	public void handleConnection(SecretKey sessionKey, Socket connection);
}
