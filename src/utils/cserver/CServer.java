package utils.cserver;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Map;
import java.util.TreeMap;

import utils.BufferUtils;
import utils.Password;
import utils.constants.Ports;
import utils.server.Server;

/**
 * Specialized server that deals with where users are (IP addresses), which
 * users are available to chat, and informing clients of the same.
 * 
 * @author Alex Dubreuil
 *
 */
public class CServer extends Server
{
	public static final String PRIMARY_KEY = "keys/cPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/cPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/cSecondary.key";
	
	/* Password is actually a data structure including twice hash of password,
	 * rather than password itself */
	Map<String, Password> registeredUsers;
	
	public boolean userExists(String name) { return registeredUsers.containsKey(name); }
	public Password getUser(String name) { return registeredUsers.get(name); }
	public boolean addUser(String name, byte[] hash2pwd, byte[] salt)
	{
		if(userExists(name))
			return false;
		registeredUsers.put(name, new Password(hash2pwd, salt));
		addUserToFile(name, hash2pwd, salt);
		return true;
	}
	
	public void addUserToFile(String name, byte[] hash2pwd, byte[] salt)
	{
		try{
			DataOutputStream dos = new DataOutputStream(new FileOutputStream("src/utils/cserver/RegisteredUsers.txt", true));
			OutputStreamWriter osw = new OutputStreamWriter(dos);
			BufferedWriter bw = new BufferedWriter(osw);
        
			bw.write(name);
			bw.newLine();
			bw.write(new String(hash2pwd));
			bw.newLine();
			bw.write(new String(salt));
			bw.newLine();
			
			bw.close();
		}
		catch (FileNotFoundException e) {e.printStackTrace();} 
		catch (IOException e) {e.printStackTrace();} 
	}
	
	public void getUsersFromFile()
	{
		 try
		 {
			 FileInputStream fis = new FileInputStream("src/utils/cserver/RegisteredUsers.txt");
			 DataInputStream dis = new DataInputStream(fis);
			 BufferedReader br = new BufferedReader(new InputStreamReader(dis));
			 
			 String name;
			 String hash2pwd;
			 String salt;
			 
			 String oneline;
			 
			 while ((oneline = br.readLine()) != null) 
			 {
			      name = oneline;
			      if(name == null)
			    	  System.err.println("name null");
			      hash2pwd = br.readLine();
			      if(hash2pwd == null)
			    	  System.err.println("hash2pwd null");
			      salt = br.readLine();
			      if(salt == null)
			    	  System.err.println("salt null");
			      registeredUsers.put(name, new Password(hash2pwd.getBytes(), salt.getBytes()));
			 }
			 
			 dis.close();
	//		 br.close();
		 }
		 catch (Exception e){e.printStackTrace();}
	}
	
	
	
	protected Map<String, byte[]> onlineUsers;
	public Map<String, byte[]> getOnlineUsers() { return onlineUsers; }
	public void updateUser(String name, byte[] ip) { onlineUsers.put(name, ip); }
	public byte[] logOffUser(String name) { return onlineUsers.remove(name); }
	
	protected byte[] sequence;
	public void sequenceIncrement() { BufferUtils.plusOne(sequence); }
	public byte[] sequence() { return sequence; }
	
	public CServer()
	{
		super(Ports.CHAT_SERVER_PORT, new CServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		registeredUsers = new TreeMap<String, Password>();
		//todo read from file to registeredUsers
		getUsersFromFile();
		onlineUsers = new TreeMap<String, byte[]>();
		sequence = new byte[4];
	}
}
