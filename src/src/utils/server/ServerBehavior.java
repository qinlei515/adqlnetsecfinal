package utils.server;

import java.net.Socket;

import utils.CipherPair;

/**
 * An interface for an object that controls how a server reacts to various Requests.
 * 
 * @author Alex Dubreuil
 *
 */
public interface ServerBehavior 
{
	public void handleConnection(CipherPair sessionCipher, Socket connection);
	public void setServer(Server s);
}
