package utils.kserver;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
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

public class KServer extends Server 
{
	public static final String PRIMARY_KEY = "keys/kPrimary.key";
	public static final String PRIMARY_PUB_KEY = "keys/kPrimaryPub.key";
	public static final String SECONDARY_KEY = "keys/kSecondary.key";
	
	protected Map<String, UserKeyData> users;
	public boolean addUser(String name, UserKeyData data) 
	{
		if(userExists(name))
			return false;
		users.put(name, data);
		addUserToFile(name, data.getPwdHash(), data.getSalt(), data.getPublicKey(), data.getPrivKeyBytes());
		return true;
	}
	
	public void addUserToFile(String name, byte[] hash2pwd, byte[] salt, byte[] pubKey, byte[] encPrivKey)
	{
		try{
	//		DataOutputStream dos = new DataOutputStream(new FileOutputStream("src/utils/kserver/users.txt", true));
	//		OutputStreamWriter osw = new OutputStreamWriter(dos);
			FileWriter fw = new FileWriter("src/utils/kserver/users.txt", true);
			BufferedWriter bw = new BufferedWriter(fw);
        
			bw.write(name);
			bw.newLine();
			bw.write(new String(hash2pwd));
			bw.newLine();
			bw.write(new String(salt));
			bw.newLine();
			bw.write(new String(pubKey));
			bw.newLine();
			bw.write(new String(encPrivKey));
			bw.newLine();
			
		//	fw.close();
			bw.flush();
			bw.close();
		}
		catch (FileNotFoundException e) {e.printStackTrace();} 
		catch (IOException e) {e.printStackTrace();} 
	}
	
	
	public void getUsersFromFile()
	{
		 try
		 {
		//	 FileInputStream fis = new FileInputStream("src/utils/kserver/users.txt");
			// DataInputStream dis = new DataInputStream(fis);
			 FileReader fr = new FileReader("src/utils/kserver/users.txt");
			 BufferedReader br = new BufferedReader(fr);
			 
			 String name;
			 String hash2pwd;
			 String salt;
			 String pubKey;
			 String encPrivKey;
			 
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
			      pubKey = br.readLine();
			      if(pubKey == null)
			    	  System.err.println("pubKey null");
			      encPrivKey = br.readLine();
			      if(encPrivKey == null)
			    	  System.err.println("encPrivKey null");
			      users.put(name, new UserKeyData(salt.getBytes(), hash2pwd.getBytes(), pubKey.getBytes(), encPrivKey.getBytes()));
			 }
			 
	//		 dis.close();
			 fr.close();
			 br.close();
		 }
		 catch (Exception e){e.printStackTrace();}
	}
	
	
	
	public byte[] getSalt(String name)
	{
		UserKeyData data = users.get(name);
		if(data == null) return null;
		return data.getSalt();
	}
	public byte[] getPrivate(String name, byte[] pwd2Hash)
	{
		UserKeyData user = users.get(name);

		if(BufferUtils.equals(user.getPwdHash(), pwd2Hash))
		{
			return user.getPrivKeyBytes();
		}
		System.err.println("User's password does not match.");
		return null;
	}
	
	public byte[] getPubKey(String name) 
	{
		UserKeyData ukd = users.get(name);
		return ukd.getPublicKey();
	}
	
	public boolean userExists(String name) { return users.containsKey(name); }
	
	public KServer()
	{
		super(Ports.KEY_SERVER_PORT, new KServerBehavior(), PRIMARY_KEY, PRIMARY_PUB_KEY, SECONDARY_KEY);
		behavior.setServer(this);
		users = new TreeMap<String, UserKeyData>();
		getUsersFromFile();
	}
}
