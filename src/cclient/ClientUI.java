package cclient;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import protocol.Protocol;
import protocol.client.ConnectionRequest;

import utils.Common;
import utils.Connection;

/**
 * The basic user interface. Accepts four commands: list, m|message, exit, help.
 * 
 * @author Alex Dubreuil
 */
public class ClientUI 
{
	protected ClientUser user;
	public ClientUser user() { return user; }
	
	protected boolean active;
	public boolean active() { return active; }
	
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
			else if(command.equals("send") || (command.equals("m") || command.equals("message")))
			{
				System.out.println("Sending " + target + " \"" + message + "\"");
				message(target, message);
			}
			else if((command.equals("exit")))
			{
				System.out.println("Goodbye.");
				user.chatLogOff();
				user.closeConnections();
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
	
	/**
	 * Attempt to send message to name. Fails if name doesn't exist or isn't logged in.
	 * 
	 * @param name
	 * @param message
	 */
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
			if(c == null)
				System.err.println("Could not send message: Connection not available.");
			else
				new DataOutputStream(c.s.getOutputStream()).write(Common.wrapMessage(message.getBytes(), c.hmac, c.cipher));
		}
		catch (IOException e) { e.printStackTrace(); }
	}
	
	private void printHelp()
	{
		System.out.println("Commands: ");
		System.out.println("  list: List all users currently logged in to the system.");
		System.out.println("  m, send, message <userID> <message>: Send a message to userID.");
		System.out.println("  exit: Close all connections and end the program.");
		System.out.println("Unimplemented: ");
		System.out.println("  kgen: Generate a new public/private key pair.");
		System.out.println("  kset: Send the current public/private key pair to the key server.");
		System.out.println("  pmod: Modify the user's password on both servers.");
	}
}
