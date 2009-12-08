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
	public void addUser(String name, UserKeyData data) { users.put(name, data); }
	
	public KServer()
	{
		super(Constants.KEY_SERVER_PORT, new KServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		((KServerBehavior)this.behavior).setServer(this);
		users = new TreeMap<String, UserKeyData>();
	}
}
