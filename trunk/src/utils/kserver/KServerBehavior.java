package utils.kserver;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;

import javax.crypto.Cipher;

import protocol.Protocol;
import protocol.Requests;
import protocol.client.Common;
import protocol.server.BadRequest;
import protocol.server.KSAdd;
import protocol.server.KSPrivate;
import protocol.server.KSPublic;
import protocol.server.KSUpdate;

import utils.BufferUtils;
import utils.server.ServerBehavior;

public class KServerBehavior implements ServerBehavior 
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
				p = new KSAdd();
			}
			else if(BufferUtils.equals(request.get(0), Requests.UPDATE))
			{
				p = new KSUpdate();
			}
			else if(BufferUtils.equals(request.get(0), Requests.PUBLIC))
			{
				p = new KSPublic();
			}
			else if(BufferUtils.equals(request.get(0), Requests.PRIVATE))
			{
				p = new KSPrivate();
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
