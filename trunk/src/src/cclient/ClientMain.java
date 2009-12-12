package cclient;

import java.io.PrintStream;

import utils.client.ClientServer;

/**
 * The main class for the client code. Processes the command line, initializes necessary
 * settings, sets up the UI.
 * 
 */
public class ClientMain 
{
	public static void main(String[] args)
	{
		ClientUser c = processCommandLine(args);
		ClientUI ui = new ClientUI(c);
		ClientServer s = new ClientServer(ui);
		
		c.initialize();
		s.run();
		ui.run();
	}
	
	private static ClientUser processCommandLine(String[] args)
	{
		int i = 0;
		ClientUser toReturn = new ClientUser();
		while(i < args.length)
		{
			if(args[i].equals("--help")) 
			{
				printUsage(System.out);
				System.exit(0);
			}
			else if(args[i].equals("-u") || args[i].equals("--user"))
			{
				i++;
				if(i < args.length) 
				{
					toReturn.setUserID(args[i]);
					System.out.println("User set to: " + args[i]);
				}
			}
			else if(args[i].equals("-cs") || args[i].equals("--chat-server"))
			{
				i++;
				if(i < args.length) toReturn.setChatServer(args[i]);
			}
			else if(args[i].equals("-ks") || args[i].equals("--key-server"))
			{
				i++;
				if(i < args.length) toReturn.setKeyServer(args[i]);
			}
			else
			{
				System.out.println(args[i] + ": not recognized.");
				printUsage(System.err);
				System.exit(-1);
			}
			i++;
		}
		return toReturn;
	}
	
	private static void printUsage(PrintStream out)
	{
		out.println("Usage: java -jar qlad_client.jar [options]");
		out.println(" options: ");
		out.println("  -u, --user <user>: Set the user");
		out.println("  -cs, --chat-server <server IP>: Set the chat server IP");
		out.println("  -ks, --key-server <server IP>: Set the PKI server IP");
		out.println("  --help: Display this message and exit");
	}
}
