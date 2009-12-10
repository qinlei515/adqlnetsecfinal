package utils.client;

import java.io.IOException;
import java.net.ServerSocket;

import protocol.client.ChatLogNotification;
import protocol.client.ConnectionAccept;

import utils.constants.Ports;
import cclient.ClientUI;

/**
 * Runs the Client's server-like behavior.
 * 
 * @author Alex Dubreuil
 *
 */
public class ClientServer 
{
	// Monitors log on|off notifications from the chat server
	protected ServerMonitor chatServerUpdates;
	// Watches for new client-client connections
	protected ServerMonitor incomingMessages;
	
	public ClientServer(ClientUI ui)
	{
		try 
		{ 
			chatServerUpdates = 
				new ServerMonitor(new ServerSocket(Ports.CHAT_NOTIFY_PORT), 
						new ChatLogNotification(ui.user()), ui);
			
			incomingMessages = 
				new ServerMonitor(new ServerSocket(Ports.MESSAGE_PORT), 
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
