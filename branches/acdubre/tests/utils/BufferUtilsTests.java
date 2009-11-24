package utils;

import junit.framework.TestCase;

public class BufferUtilsTests extends TestCase 
{
	byte[] a;
	byte[] b;
	byte[] shiftedA;
	byte[] abconcat;
	
	public void setUp()
	{
		a = "String".getBytes();
		b = "Another".getBytes();
		shiftedA = new byte[a.length + 5];
		for(int i = 0; i < 5; i++)
			shiftedA[i] = 0;
		for(int i = 0; i < a.length; i++)
			shiftedA[i+5] = a[i];
		abconcat = "StringAnother".getBytes();
	}
	
	public void test_copy()
	{
		byte[] copy = new byte[a.length];
		utils.BufferUtils.copy(a, copy, a.length);
		assertEquals(a, copy);
	}
	
	public void test_copy_with_offsets()
	{
		byte[] copy = new byte[a.length];
		utils.BufferUtils.copy(a, copy, a.length, 0, 0);
		assertEquals(a, copy);
		utils.BufferUtils.copy(a, copy, a.length, 0, 5);
		assertEquals(shiftedA, copy);
		utils.BufferUtils.copy(shiftedA, copy, a.length, 5, 0);
		assertEquals(a, copy);
	}
	
	public void test_concat()
	{
		assertEquals(abconcat, utils.BufferUtils.concat(a, b));
	}
	
	public void test_translate()
	{
		int i1 = 25;
		byte[] a1 = BufferUtils.translate(i1);
		byte[] t1 = new byte[2]; t1[0] = (byte)25; t1[1] = (byte)0;
		assertTrue(BufferUtils.equals(a1, t1));
		int i2 = 2560;
		byte[] a2 = BufferUtils.translate(i2);
		byte[] t2 = new byte[2]; t2[0] = (byte)0; t2[1] = (byte)10;
		assertTrue(BufferUtils.equals(a2, t2));
	}
}
