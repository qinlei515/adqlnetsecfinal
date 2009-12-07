package cserver;

import java.io.IOException;

import utils.cserver.CServer;
import utils.server.Server;

public class ChatMain 
{
	public static void main(String[] args) throws IOException
	{
		Server s = new CServer();
		s.run();
	}
}
