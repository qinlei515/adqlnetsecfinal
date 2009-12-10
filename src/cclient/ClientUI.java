package cclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import protocol.Protocol;
import protocol.client.ConnectionRequest;

import utils.Common;
import utils.Connection;

public class ClientUI 
{
	protected ClientUser user;
	protected boolean active;
	
	public ClientUI(ClientUser user) 
	{ 
		this.user = user; 
	}
	
	public void run()
	{
		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		active = true;
		String nextLine;
		String command = "";
		String target = "";
		String message = "";
		while(active)
		{
			System.out.print("> ");
			try { nextLine = input.readLine(); }
			catch(IOException e) { e.printStackTrace(); nextLine = ""; }
			
			int nextSpace = nextLine.indexOf(" ");
			if(nextSpace == -1) { command = nextLine; }
			else
			{
				command = nextLine.substring(0, nextSpace);
				nextLine = nextLine.substring(nextSpace+1, nextLine.length());
				nextSpace = nextLine.indexOf(" ");
			
				if(nextSpace == -1) { target = nextLine; }
				else
				{
					target = nextLine.substring(0, nextSpace);
					message = nextLine.substring(nextSpace+1, nextLine.length());
				}
			}
			
			if((command.equals("list")))
			{
				System.out.println("Currently logged in users:");
				for(String uid : user.getUsers().keySet())
					System.out.println(uid + " " + user.getUsers().get(uid));
			}
			else if((command.equals("m") || command.equals("message")))
			{
				System.out.println("Sending " + target + " \"" + message + "\"");
				message(target, message);
			}
			else if((command.equals("exit")))
			{
				System.out.println("Goodbye.");
				try { if(user.getChatServer() != null) user.getChatServer().close(); } 
				catch (IOException e) { e.printStackTrace(); }
				try { if(user.getKeyServer() != null) user.getKeyServer().close(); } 
				catch (IOException e) { e.printStackTrace(); }
				active = false;
			}
			else if(command.equals("help")) { printHelp(); }
			else { System.err.println("Command: " + command + " not recognized."); }
		}
	}
	
	private void message(String name, String message)
	{
		Connection c = user.getConnection(name);
		if(c == null)
		{
			Protocol p = new ConnectionRequest(name, user);
			p.run(new Connection());
			c = user.getConnection(name);
		}
		try 
		{
			c.s.getOutputStream().write(Common.wrapMessage(message.getBytes(), c.hmac, c.cipher));
		}
		catch (IOException e) { e.printStackTrace(); }
	}
	
	private void printHelp()
	{
		System.out.println("Commands: ");
		System.out.println("  u, user <userID>: Set the current user.");
		System.out.println("  cs, chat-server <chat server IP>: Set the chat server IP.");
		System.out.println("  clogin: Login to the current chat server.");
		System.out.println("  m, message <userID> <message>: Send a message to userID.");
		System.out.println("  ks, key-server <key server IP>: Set the key server IP.");
		System.out.println("  kgen: Generate a new public/private key pair.");
		System.out.println("  kget: Retrieve the public/private key pair of the current user.");
		System.out.println("  kset: Send the current public/private key pair to the key server.");
	}
}
