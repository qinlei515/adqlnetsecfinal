package utils.server;

import java.net.Socket;

import javax.crypto.Cipher;

public interface ServerBehavior 
{
	public void handleConnection(Cipher sessionCipher, Socket connection);
}
