package utils.server;

import java.net.Socket;

import javax.crypto.Cipher;

import utils.CipherPair;

public interface ServerBehavior 
{
	public void handleConnection(CipherPair sessionCipher, Socket connection);
}
