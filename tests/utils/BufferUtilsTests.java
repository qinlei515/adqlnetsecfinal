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
}
