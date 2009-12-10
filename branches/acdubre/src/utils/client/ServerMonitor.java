package utils.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import cclient.ClientUI;

import protocol.Protocol;

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
		while(ui.active())
		{
			try { synchronized(this) { this.wait(100); }} 
			catch (InterruptedException e) { e.printStackTrace(); }
			try 
			{ 
				Socket connection = socket.accept();
				new Thread(new ClientConnectionHandler(connection, p)).start();
			} 
			catch (IOException e) { e.printStackTrace(); }
		}
	}
}
