package utils.kserver;

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
import utils.constants.Ports;
import utils.exceptions.ConnectionClosedException;
import utils.server.Server;

public class KServer extends Server 
{
	public static final String PRIMARY_KEY = "keys/kPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/kPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/kSecondary.key";

	public static final String USERS_FILE = "data/ks_users";

	protected Map<String, UserKeyData> users;
	public boolean addUser(String name, UserKeyData data) 
	{
		if(userExists(name))
			return false;
		users.put(name, data);
		addUserToFile(name, data.getPwdHash(), data.getSalt(), data.getPublicKey(), data.getPrivKeyBytes());
		return true;
	}

	public void addUserToFile(String name, byte[] hash2pwd, byte[] salt, byte[] pubKey, byte[] encPrivKey)
	{
		try
		{		
			FileOutputStream outputFile = 
				new FileOutputStream(USERS_FILE, true);
			DataOutputStream output = new DataOutputStream(outputFile);

			byte[] user = 
				Common.createMessage(name.getBytes(), salt, hash2pwd, pubKey, encPrivKey);
			output.write(user);
			output.flush();
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
				users.put(new String(user.get(0)), new UserKeyData(user.get(1), user.get(2), user.get(3), user.get(4)));
				try { user = Common.getResponse(usersIn); }
				catch (ConnectionClosedException e) { user = null; }
			}
			usersInFile.close();
			usersIn.close();
		}
		catch (IOException e){e.printStackTrace();}
		
	}



	public byte[] getSalt(String name)
	{
		UserKeyData data = users.get(name);
		if(data == null) return null;
		return data.getSalt();
	}
	public byte[] getPrivate(String name, byte[] pwd2Hash)
	{
		UserKeyData user = users.get(name);

		if(BufferUtils.equals(user.getPwdHash(), pwd2Hash))
		{
			return user.getPrivKeyBytes();
		}
		System.err.println("User's password does not match.");
		return null;
	}

	public byte[] getPubKey(String name) 
	{
		UserKeyData ukd = users.get(name);
		return ukd.getPublicKey();
	}

	public boolean userExists(String name) { return users.containsKey(name); }

	public KServer()
	{
		super(Ports.KEY_SERVER_PORT, new KServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		users = new TreeMap<String, UserKeyData>();
		getUsersFromFile();
	}
}
