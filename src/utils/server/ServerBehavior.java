package utils.server;

import java.net.Socket;

import utils.CipherPair;

public interface ServerBehavior 
{
	public void handleConnection(CipherPair sessionCipher, Socket connection);
	public void setServer(Server s);
}
