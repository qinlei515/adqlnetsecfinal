package utils;

public class BufferUtils 
{
	public static void copy(byte[] from, byte[] to, int numToCopy)
	{
		for(int i = 0; i < numToCopy; i++)
			to[i] = from[i];
	}
	
	// Offset in from array
	public static void copy(byte[] from, byte[] to, int numToCopy, int fromOffset, int toOffset)
	{
		for(int i = 0; i < numToCopy; i++)
		{
			to[toOffset+i] = from[fromOffset+i];
		}
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
	
	public static byte[] concat(byte[] a, byte[] b)
	{
		byte[] answer = new byte[a.length + b.length];
		copy(a, answer, a.length);
		println(answer);
		copy(b, answer, b.length, 0, a.length);
		return answer;
	}
	
	public static void print(byte[] a)
	{
		for(byte b : a)
			System.out.print(b + " ");
	}
	public static void println(byte[] a)
	{
		print(a);
		System.out.println();
	}
}
