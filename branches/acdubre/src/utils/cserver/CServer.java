package utils.cserver;

import java.util.Map;
import java.util.TreeMap;

import utils.Constants;
import utils.server.Server;

public class CServer extends Server
{
	public static final String PRIMARY_KEY = "keys/cPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/cPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/cSecondary.key";
	
	Map<String, byte[]> registeredUsers;
	public boolean userExists(String name) { return registeredUsers.containsKey(name); }
	public boolean addUser(String name, byte[] hash2pwd)
	{
		if(userExists(name))
			return false;
		registeredUsers.put(name, hash2pwd);
		return true;
	}
	Map<String, String> onlineUsers;
	
	public CServer()
	{
		super(Constants.CHAT_SERVER_PORT, new CServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		registeredUsers = new TreeMap<String, byte[]>();
		onlineUsers = new TreeMap<String, String>();
	}
}
