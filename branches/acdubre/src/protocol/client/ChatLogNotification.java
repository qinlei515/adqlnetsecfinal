package protocol.client;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;

import cclient.ClientUser;

import protocol.Protocol;
import protocol.Requests;
import utils.BufferUtils;
import utils.Common;
import utils.Connection;
import utils.constants.Keys;
import utils.exceptions.ConnectionClosedException;

/**
 * Client side of a client-server protocol, used to handle a chat log notification.
 * 
 * Either adds or removes a specified user from the active users map.
 * 
 * @author Alex Dubreuil
 *
 */
public class ChatLogNotification implements Protocol 
{
	ClientUser user;
	
	public ChatLogNotification(ClientUser user)
	{
		this.user = user;
	}
	
	public boolean run(Connection c) 
	{
		try 
		{
			ArrayList<byte[]> update = 
				Common.getResponse(new DataInputStream(c.s.getInputStream()));
			if(update.size() != 2) { return false; }
			byte[] message = update.get(0);
			byte[] mac = update.get(1);
			
			if(Common.verify(mac, message, Keys.getCServerPrimaryKey()))
			{
				update = Common.splitResponse(message);
				if(update.size() != 4) { return false; }
				byte[] event = update.get(0);
				byte[] name = update.get(1);
				byte[] ip = update.get(2);
				byte[] sequence = update.get(3);
				
				if(BufferUtils.equals(sequence, user.sequence()))
				{
					if(BufferUtils.equals(event, Requests.LOG_ON))
					{
						user.addUser(BufferUtils.translateString(name), 
								BufferUtils.translateIPAddress(ip));
						user.incrementSequence();
					}
					else if(BufferUtils.equals(event, Requests.LOG_OFF))
					{
						user.removeUser(BufferUtils.translateString(name));
						user.incrementSequence();
					}
				}
			}
		}
		catch (IOException e) { e.printStackTrace(); }
		catch (ConnectionClosedException e) {
			try { c.s.close(); }
			catch (IOException e1) {
				e1.printStackTrace();
			}
		}
		return false;
	}

}
