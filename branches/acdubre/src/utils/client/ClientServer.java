package utils.client;

import java.io.IOException;
import java.net.ServerSocket;

import protocol.client.ChatLogNotification;
import protocol.client.ConnectionAccept;

import utils.Constants;
import cclient.ClientUI;

public class ClientServer 
{
	protected ServerMonitor chatServerUpdates;
	protected ServerMonitor incomingMessages;
	
	public ClientServer(ClientUI ui)
	{
		try 
		{ 
			chatServerUpdates = 
				new ServerMonitor(new ServerSocket(Constants.CHAT_NOTIFY_PORT), 
						new ChatLogNotification(ui.user()), ui);
			
			incomingMessages = 
				new ServerMonitor(new ServerSocket(Constants.MESSAGE_PORT), 
						new ConnectionAccept(ui.user()), ui);
		}
		catch (IOException e) { e.printStackTrace(); }
	}
	
	public void run()
	{
		new Thread(chatServerUpdates).start();
		new Thread(incomingMessages).start();
	}
}
