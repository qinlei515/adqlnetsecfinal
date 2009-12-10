package utils.client;

import java.io.IOException;
import java.net.ServerSocket;

import protocol.client.ChatLogNotification;
import protocol.client.ConnectionAccept;

import utils.Constants;
import cclient.ClientUser;

public class ClientServer 
{
	protected ClientUser user;
	protected ServerMonitor chatServerUpdates;
	protected ServerMonitor incomingMessages;
	
	public ClientServer(ClientUser user)
	{
		this.user = user;
		try 
		{ 
			chatServerUpdates = 
				new ServerMonitor(new ServerSocket(Constants.CHAT_SERVER_PORT), 
						new ChatLogNotification(user));
			
			incomingMessages = 
				new ServerMonitor(new ServerSocket(Constants.MESSAGE_PORT), 
						new ConnectionAccept(user));
		}
		catch (IOException e) { e.printStackTrace(); }
	}
	
	public void run()
	{
		new Thread(chatServerUpdates).run();
		new Thread(incomingMessages).run();
	}
}
