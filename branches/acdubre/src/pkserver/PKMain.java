package pkserver;

import java.io.IOException;

import utils.kserver.KServer;

/**
 * Main class to start a key server.
 * 
 * @author Alex Dubreuil
 */
public class PKMain 
{
	public static void main(String[] args) throws IOException
	{
		new KServer().run();
	}
}