package utils;

public class BufferUtils 
{
	public static void copy(byte[] from, byte[] to, int numToCopy)
	{
		for(int i = 0; i < numToCopy; i++)
			to[i] = from[i];
	}
	
	// Offset in from array
	public static void copy(byte[] from, byte[] to, int numToCopy, int offset)
	{
		for(int i = 0; i < numToCopy; i++)
			to[i] = from[offset+i];
	}
	
	public static boolean equals(byte[] a, byte[] b)
	{
		boolean answer = a.length == b.length;
		int i = 0;
		while(answer && i < a.length)
		{
			answer &= a[i] == b[i];
			i++;
		}
		return answer;		
	}
}
