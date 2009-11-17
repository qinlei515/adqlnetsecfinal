package pkserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

public class PKMain 
{
	public static void main(String[] args) throws IOException
	{
		ServerSocket s = new ServerSocket(utils.Constants.KEY_SERVER_PORT);
		Socket service = s.accept();
		BufferedReader input = new BufferedReader(new InputStreamReader(service.getInputStream()));
		System.out.println(input.readLine());
	}
}
