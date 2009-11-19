package protocol.kserver;

import java.io.IOException;
import java.net.Socket;

import javax.crypto.spec.DHParameterSpec;

public class AddReceive 
{

	
	public boolean doReceive(DHParameterSpec ourSpecs, Socket client)
	{
		try 
		{
			KSCommon.provideChallenge1(client);
		} 
		catch (IOException e) {	e.printStackTrace(); }
		return false;
	}
}
