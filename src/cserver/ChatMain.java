package cserver;

import java.io.IOException;

import utils.cserver.CServer;

/**
 * Main class to start a chat server.
 * 
 * @author Alex Dubreuil
 */
public class ChatMain 
{
	public static void main(String[] args) throws IOException
	{
		new CServer().run();
	}
}