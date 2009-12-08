package utils.cserver;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;

import javax.crypto.Cipher;

import protocol.Protocol;
import protocol.Requests;
import protocol.client.Common;
import protocol.server.BadRequest;
import protocol.server.CSAdd;
import protocol.server.CSLogOff;
import protocol.server.CSLogOn;
import protocol.server.CSUpdate;

import utils.BufferUtils;
import utils.server.ServerBehavior;

public class CServerBehavior implements ServerBehavior 
{
	public void handleConnection(Cipher sessionCipher, Socket connection) 
	{
		try
		{
			DataInputStream fromClient = new DataInputStream(connection.getInputStream());
			
			ArrayList<byte[]> request = Common.getResponse(fromClient);
			Protocol p;
			
			if(BufferUtils.equals(request.get(0), Requests.ADD))
			{
				p = new CSAdd();
			}
			else if(BufferUtils.equals(request.get(0), Requests.UPDATE))
			{
				p = new CSUpdate();
			}
			else if(BufferUtils.equals(request.get(0), Requests.LOG_ON))
			{
				p = new CSLogOn();
			}
			else if(BufferUtils.equals(request.get(0), Requests.LOG_OFF))
			{
				p = new CSLogOff();
			}
			else
			{
				p = new BadRequest();
			}
			p.run(connection, sessionCipher);
		}
		catch(IOException e) { e.printStackTrace(); }
	}

}
