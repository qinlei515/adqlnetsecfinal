package utils.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import cclient.ClientUI;

import protocol.Protocol;

/**
 * Watches for a specific type of incoming connection for a client.
 *
 */
public class ServerMonitor implements Runnable
{
	ServerSocket socket;
	Protocol p;
	ClientUI ui;
	
	public ServerMonitor(ServerSocket toMonitor, Protocol p, ClientUI ui)
	{
		this.socket = toMonitor;
		this.p = p;
		this.ui = ui;
	}
	
	public void run() 
	{
		try { socket.setSoTimeout(100); }
		catch (SocketException e1) { e1.printStackTrace(); }
		
		while(ui.active())
		{
			try { synchronized(this) { this.wait(100); }} 
			catch (InterruptedException e) { e.printStackTrace(); }
			try 
			{ 
				Socket connection = socket.accept();
				new Thread(new ClientConnectionHandler(connection, p)).start();
			} 
			// We expect these. They let us exit the client when we're done.
			catch (SocketTimeoutException e) {}
			catch (IOException e) { e.printStackTrace(); }		
		}
	}
}
