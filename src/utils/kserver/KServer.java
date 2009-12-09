package utils.kserver;

import java.util.Map;
import java.util.TreeMap;

import utils.Constants;
import utils.server.Server;

public class KServer extends Server 
{
	public static final String PRIMARY_KEY = "keys/kPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/kPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/kSecondary.key";
	
	protected Map<String, UserKeyData> users;
	public boolean addUser(String name, UserKeyData data) 
	{
		if(userExists(name))
			return false;
		users.put(name, data);
		return true;
	}
	
	public byte[] getPubKey(String name) 
	{
		UserKeyData ukd = users.get(name);
		return ukd.getPublicKey();
	}
	
	public boolean userExists(String name) { return users.containsKey(name); }
	
	public KServer()
	{
		super(Constants.KEY_SERVER_PORT, new KServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		users = new TreeMap<String, UserKeyData>();
	}
}
