package cclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.SecureRandom;

import sun.security.rsa.RSAKeyPairGenerator;

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
			
			if((command.equals("u") || command.equals("user")))
			{
				user.setUserID(target);
				System.out.println("User set to: " + user.getUserID());
			}
			else if((command.equals("m") || command.equals("message")))
			{
				System.out.println("Sending " + target + " \"" + message + "\"");
			}
			else if((command.equals("cs") || command.equals("chat-server")))
			{
				user.setChatServerIP(target);
				System.out.println("Chat server set to: " + user.getChatServer());
			}
			else if((command.equals("ks") || command.equals("key-server")))
			{
				user.setKeyServer(target);
				System.out.println("Key server set to: " + user.getChatServer());
			}
			else if(command.equals("kgen") || command.equals("keygen"))
			{
				RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
				gen.initialize(utils.Constants.RSA_KEY_SIZE, new SecureRandom());
				KeyPair kp = gen.generateKeyPair();
				user.setPrivateKey(kp.getPrivate());
				user.setPublicKey(kp.getPublic());
			}
			else if(command.equals("kset") || command.equals("keyset"))
			{
				boolean set = true;
				if(user.getUserID() == null)
				{
					System.err.println("User not set.");
					set = false;
				}
				if(user.getKeyServer() == null)
				{
					System.err.println("Key server not set.");
					set = false;
				}
				if(user.getPublicKey() == null)
				{
					System.err.println("Public key not set.");
					set = false;
				}
				if(user.getPrivateKey() == null)
				{
					System.err.println("Private key not set");
					set = false;
				}
				if(set)
				{
					//TODO: Push the current keys to the key server.
				}
			}
			else if(command.equals("kget") || command.equals("keyget"))
			{
				boolean get = true;
				if(user.getUserID() == null)
				{
					System.err.println("User not set.");
					get = false;
				}
				if(user.getKeyServer() == null)
				{
					System.err.println("Key server not set.");
					get = false;
				}
				if(get)
				{
					//TODO: Get the user's keys. 
				}
			}
			else if(command.equals("clogin") || command.equals("chatlogin"))
			{
				boolean login = true;
				if(user.getUserID() == null)
				{
					System.err.println("User not set.");
					login = false;
				}
				if(user.getChatServer() == null)
				{
					System.err.println("Chat server not set.");
					login = false;
				}
				if(user.getPublicKey() == null)
				{
					System.err.println("Public key not set.");
					login = false;
				}
				if(user.getPrivateKey() == null)
				{
					System.err.println("Private key not set");
					login = false;
				}
				if(login)
				{
					//TODO: Authenticate to the chat server.
				}
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
