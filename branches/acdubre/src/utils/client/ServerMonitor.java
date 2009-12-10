package utils.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import protocol.Protocol;

public class ServerMonitor implements Runnable
{
	ServerSocket socket;
	Protocol p;
	
	public ServerMonitor(ServerSocket toMonitor, Protocol p)
	{
		this.socket = toMonitor;
		this.p = p;
	}
	
	public void run() 
	{
		while(true)
		{
			try { synchronized(this) { this.wait(1); }} 
			catch (InterruptedException e) { e.printStackTrace(); }
			try 
			{ 
				Socket connection = socket.accept();
				new Thread(new ClientConnectionHandler(connection, p)).run();
			} 
			catch (IOException e) { e.printStackTrace(); }
		}
	}
}
