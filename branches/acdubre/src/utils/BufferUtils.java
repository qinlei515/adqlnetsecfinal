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
	
	public static byte[] concat(byte[]... toConcat)
	{
		int totalSize = 0;
		for(byte[] b : toConcat)
			totalSize += b.length;
		byte[] answer = new byte[totalSize];
		int pos = 0;
		for(byte[] b : toConcat)
		{
			copy(answer, b, b.length, 0, pos);
			pos += b.length;
		}
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
	
	public static byte[] translate(Integer i)
	{
		byte[] answer = new byte[2];
		answer[0] = new Integer(i % 256).byteValue();
		answer[1] = new Integer(i / 256).byteValue();
		return answer;
	}
	public static int translate(int high, int low) { return high * 256 + low; }
	
	// Generate a random number as an array of bytes.
	public static byte[] random(int byteSize)
	{
		byte[] answer = new byte[byteSize];
		// TODO: Is Math.random() cryptographically secure as a RNG?
		for(int i = 0; i < byteSize; i++)
			answer[i] = (byte)(Math.random() * Byte.MAX_VALUE);
		return answer;
	}
}
