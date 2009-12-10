package protocol.server;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Map;

import protocol.Protocol;
import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Connection;
import utils.constants.Ports;
import utils.cserver.CServer;

/**
 * A broadcast in name, not in implementation. Used to distribute changes in the
 * active user list to clients.
 * 
 * @author Alex Dubreuil
 */
public class ChatLogBroadcast implements Protocol
{
	Map<String, byte[]> activeUsers;
	byte[] message;
	
	
	
	public ChatLogBroadcast(CServer server, String user, byte[] ip, byte[] event)
	{
		this.activeUsers = server.getOnlineUsers();
		byte[] tempMessage = Common.createMessage(event, 
				user.getBytes(), 
				ip,
				server.sequence());
		byte[] mac = server.sign(tempMessage);
		message = Common.createMessage(tempMessage, mac);
	}

	public boolean run(Connection c) { return run(c.s, c.cipher); }
	
	/**
	 * Both arguments are unused in this particular protocol.
	 */
	public boolean run(Socket connection, CipherPair sessionCipher) 
	{
		
		Socket s;
		for(String user : activeUsers.keySet())
		{
			System.out.println("Sending " + user + " log notification.");
			try
			{
				s = new Socket(BufferUtils.translateIPAddress(activeUsers.get(user)), Ports.CHAT_NOTIFY_PORT);
				new DataOutputStream(s.getOutputStream()).write(message);
				s.close();
			}
			catch (UnknownHostException e) { e.printStackTrace(); }
			catch (IOException e) { e.printStackTrace(); }
		}
		return true;
	}

}
