package utils.kserver;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;

import protocol.Protocol;
import protocol.Requests;
import protocol.server.BadRequest;
import protocol.server.KSAdd;
import protocol.server.KSPrivate;
import protocol.server.KSPublic;
import protocol.server.KSUpdate;

import utils.BufferUtils;
import utils.CipherPair;
import utils.Common;
import utils.Constants;
import utils.server.Server;
import utils.server.ServerBehavior;

public class KServerBehavior implements ServerBehavior 
{
	KServer server;
	public void setServer(Server server) { this.server = (KServer)server; }
	
	public void handleConnection(CipherPair sessionCipher, Socket connection) 
	{
		try
		{
			DataInputStream fromClient = new DataInputStream(connection.getInputStream());
			
			ArrayList<byte[]> request = Common.getResponse(fromClient);
			
			byte[] iv = request.get(0);
			byte[] encrMessage = request.get(1);
			byte[] mac = request.get(2);
			
			sessionCipher.initDecrypt(iv);
			byte[] message = sessionCipher.decrypt.doFinal(encrMessage);
			
			// Check integrity
			Mac hmac = Mac.getInstance(Constants.HMAC_SHA1_ALG);
			hmac.init(sessionCipher.key);
			if(!BufferUtils.equals(mac, hmac.doFinal(message)))
			{
				System.err.println("Failed integrity check.");
				return;
			}
			
			request = Common.splitResponse(message);
			System.out.println(BufferUtils.translateString(request.get(0)));
			
			Protocol p;
			
			if(BufferUtils.equals(request.get(0), Requests.ADD) && request.size() == 4)
			{
				p = new KSAdd(request.get(1), request.get(2), request.get(3), server);
			}
			else if(BufferUtils.equals(request.get(0), Requests.UPDATE))
			{
				p = new KSUpdate();
			}
			else if(BufferUtils.equals(request.get(0), Requests.PUBLIC))
			{
				p = new KSPublic(request.get(1), server);
			}
			else if(BufferUtils.equals(request.get(0), Requests.PRIVATE))
			{
				p = new KSPrivate();
			}
			else
			{
				System.err.print("Bad request: ");
				BufferUtils.println(request.get(0));
				p = new BadRequest();
			}
			if(p.run(connection, sessionCipher)) 
				System.out.println("Protocol completed successfully.");
			
			connection.close();
		}
		catch(IOException e) { e.printStackTrace(); } 
		catch (IllegalBlockSizeException e) { e.printStackTrace(); } 
		catch (BadPaddingException e) { e.printStackTrace(); } 
		catch (NoSuchAlgorithmException e) { e.printStackTrace(); } 
		catch (InvalidKeyException e) { e.printStackTrace(); }
	}

}
