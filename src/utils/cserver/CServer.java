package utils.cserver;

import utils.Constants;
import utils.server.Server;

public class CServer extends Server
{
	public static final String PRIMARY_KEY = "keys/cPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/cPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/cSecondary.key";
	
	
	public CServer()
	{
		super(Constants.CHAT_SERVER_PORT, new CServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
	}
}
