package utils.cserver;

import java.util.Map;
import java.util.TreeMap;

import utils.Common;
import utils.Constants;
import utils.Password;
import utils.server.Server;

public class CServer extends Server
{
	public static final String PRIMARY_KEY = "keys/cPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/cPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/cSecondary.key";
	
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
		return true;
	}
	
	protected Map<String, byte[]> onlineUsers;
	public Map<String, byte[]> getOnlineUsers() { return onlineUsers; }
	public void updateUser(String name, byte[] ip) { onlineUsers.put(name, ip); }
	public byte[] logOffUser(String name) { return onlineUsers.remove(name); }
	
	protected byte[] sequence;
	public void sequenceIncrement() { Common.plusOne(sequence); }
	public byte[] sequence() { return sequence; }
	
	public CServer()
	{
		super(Constants.CHAT_SERVER_PORT, new CServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		registeredUsers = new TreeMap<String, Password>();
		onlineUsers = new TreeMap<String, byte[]>();
		sequence = new byte[4];
	}
}
