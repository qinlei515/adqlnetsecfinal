package pkserver;

import java.io.IOException;

import utils.kserver.KServer;
import utils.server.Server;

public class PKMain 
{
	public static void main(String[] args) throws IOException
	{
		Server s = new KServer();
		s.run();
	}
}
