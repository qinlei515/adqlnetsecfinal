package utils.cserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import utils.BufferUtils;
import utils.Common;
import utils.Password;
import utils.constants.Ports;
import utils.exceptions.ConnectionClosedException;
import utils.server.Server;

/**
 * Specialized server that deals with where users are (IP addresses), which
 * users are available to chat, and informing clients of the same.
 * 
 * @author Alex Dubreuil
 *
 */
public class CServer extends Server
{
	public static final String PRIMARY_KEY = "keys/cPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/cPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/cSecondary.key";
	
	public static final String USERS_FILE = "data/cs_users";

	/* Password is actually a data structure including twice hash of password,
	 * rather than password itself */
	Map<String, Password> registeredUsers;

	public boolean userExists(String name) { return registeredUsers.containsKey(name); }
	public Password getUser(String name) { return registeredUsers.get(name); }
	public boolean addUser(String name, byte[] hash2pwd, byte[] salt)
	{
		if(userExists(name))
			return false;
		registeredUsers.put(name, new Password(hash2pwd, salt));
		addUserToFile(name, hash2pwd, salt);
		return true;
	}

	public void addUserToFile(String name, byte[] hash2pwd, byte[] salt)
	{
		try{
			FileOutputStream outputFile = new FileOutputStream(USERS_FILE, true);
			DataOutputStream output = new DataOutputStream(outputFile);

			byte[] user = Common.createMessage(name.getBytes(), hash2pwd, salt);
			output.write(user);
			output.close();
		}
		catch (FileNotFoundException e) {e.printStackTrace();} 
		catch (IOException e) {e.printStackTrace();} 
	}

	public void getUsersFromFile()
	{
		try
		{
			File usersFile = new File(USERS_FILE);
			FileInputStream usersInFile = new FileInputStream(usersFile);
			DataInputStream usersIn = new DataInputStream(usersInFile);

			ArrayList<byte[]> user;
			try { user = Common.getResponse(usersIn); }
			// Means the file is empty, in this case.
			catch (ConnectionClosedException e1) { user = null; }

			while(user != null)
			{
				registeredUsers.put(new String(user.get(0)), new Password(user.get(1), user.get(2)));
				try { user = Common.getResponse(usersIn); }
				catch (ConnectionClosedException e) { user = null; }
			}
			usersInFile.close();
			usersIn.close();
		}
		catch (IOException e){e.printStackTrace();}
	}



	protected Map<String, byte[]> onlineUsers;
	public Map<String, byte[]> getOnlineUsers() { return onlineUsers; }
	public void updateUser(String name, byte[] ip) { onlineUsers.put(name, ip); }
	public byte[] logOffUser(String name) { return onlineUsers.remove(name); }

	protected byte[] sequence;
	public void sequenceIncrement() { BufferUtils.plusOne(sequence); }
	public byte[] sequence() { return sequence; }

	public CServer()
	{
		super(Ports.CHAT_SERVER_PORT, new CServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		registeredUsers = new TreeMap<String, Password>();
		//todo read from file to registeredUsers
		getUsersFromFile();
		onlineUsers = new TreeMap<String, byte[]>();
		sequence = new byte[4];
	}
}
