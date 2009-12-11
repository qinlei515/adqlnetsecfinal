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

import utils.Password;

public class test {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try{
			DataOutputStream out = new DataOutputStream(new FileOutputStream("src/utils/cserver/RegisteredUsers.txt"));
			OutputStreamWriter osw = new OutputStreamWriter(out);
			BufferedWriter bw = new BufferedWriter(osw);
        
			bw.write("Writing line one to file");
			bw.newLine();
			bw.write("Writing line two to file");
			bw.close();
		}
		catch (FileNotFoundException e) {e.printStackTrace();} 
		catch (IOException e) {e.printStackTrace();} 
		
		 try
		 {
			 FileInputStream fis = new FileInputStream("src/utils/cserver/RegisteredUsers.txt");
			 DataInputStream dis = new DataInputStream(fis);
			 BufferedReader br = new BufferedReader(new InputStreamReader(dis));
			 
			 
			 String oneline;
			 
			 while ((oneline = br.readLine()) != null) 
			 {
			      System.out.println(oneline);
			      System.out.println(br.readLine());
			 }
			 
			 dis.close();
			 br.close();
		 }
		 catch (Exception e){e.printStackTrace();}
		
		/*
		 try {
		        BufferedWriter out = new BufferedWriter(new FileWriter("src/utils/cserver/RegisteredUsers.txt"));
		        out.write("Writing line one to file");
		        out.newLine();
				out.write("Writing line two to file");
		        out.close();
		    } catch (IOException e) {
		    }
		    */

	}

}
