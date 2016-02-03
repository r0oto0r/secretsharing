/**
 * The MIT License (MIT)
 * Copyright (c) 2016 Benjamin Weigl
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package secret.sharing.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

import org.junit.Test;

import secret.sharing.ShareHolder;

public class ShareHolderTest {

	private static SecureRandom mRandomNumberGenerator = new SecureRandom();
	
	@Test
	public void CanCreateShareHolder()
	{
		ShareHolder shareHolder = new ShareHolder(2, 2);
		assertNotNull(shareHolder);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void CanNotCreateShareHolderWithTooSmallThreshold()
	{
		new ShareHolder(2, 1);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void CanNotCreateShareHolderWithTooSmallIndex()
	{
		new ShareHolder(0, 2);
	}
	
	@Test
	public void CanInitBunchOfPlainShareholder()
	{
		int shareHolderCount = 100;
		ShareHolder[] shareHolder = ShareHolder.initShareHolder(shareHolderCount, 2);
		assertNotNull(shareHolder);
		assertEquals(shareHolderCount, shareHolder.length);
	}
	
	@Test
	public void CanBeSerialized() throws IOException
	{
		ShareHolder shareHolder = new ShareHolder(2, 2);
		assertNotNull(shareHolder);
		
		byte[] share1 = new byte[16];
		byte[] share2 = new byte[12];
		byte[] share3 = new byte[50];
		
		mRandomNumberGenerator.nextBytes(share1);
		mRandomNumberGenerator.nextBytes(share2);
		mRandomNumberGenerator.nextBytes(share3);
		
		shareHolder.AddShare(share1);
		shareHolder.AddShare(share2);
		shareHolder.AddShare(share3);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(bos);
		out.writeObject(shareHolder);
		out.close();
		
		byte[] object = bos.toByteArray();
		assertNotNull(object);
	}
	
	@Test
	public void CanBeDeserialized() throws IOException, ClassNotFoundException
	{
		ShareHolder shareHolder = new ShareHolder(2, 2);
		assertNotNull(shareHolder);
		
		byte[] share1 = new byte[16];
		byte[] share2 = new byte[12];
		byte[] share3 = new byte[50];
		
		mRandomNumberGenerator.nextBytes(share1);
		mRandomNumberGenerator.nextBytes(share2);
		mRandomNumberGenerator.nextBytes(share3);
		
		shareHolder.AddShare(share1);
		shareHolder.AddShare(share2);
		shareHolder.AddShare(share3);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		ObjectOutputStream out = new ObjectOutputStream(bos);
		out.writeObject(shareHolder);
		out.close();
		
		byte[] object = bos.toByteArray();
		assertNotNull(object);
		
		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(object));
		ShareHolder shareHolder2 = (ShareHolder) in.readObject();
		in.close();
		
		assertEquals(shareHolder.GetBlockCount(), shareHolder2.GetBlockCount());
		assertEquals(shareHolder.GetIndex(), shareHolder2.GetIndex());
		assertEquals(shareHolder.GetThreshold(), shareHolder2.GetThreshold());
		assertArrayEquals(shareHolder.GetShare(0), shareHolder2.GetShare(0));
		assertArrayEquals(shareHolder.GetShare(1), shareHolder2.GetShare(1));
		assertArrayEquals(shareHolder.GetShare(2), shareHolder2.GetShare(2));
	}
}
