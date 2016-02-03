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

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.junit.Before;
import org.junit.Test;

import secret.sharing.Dealer;
import secret.sharing.ShareHolder;

public class DealerTest
{
	private static final SecureRandom mRandomNumberGenerator = new SecureRandom();
	
	private byte[] trivialRandomData = new byte[1];
	private byte[] perfectRandomData = new byte[16];
	private byte[] smallRandomData = new byte[51];
	private byte[] bigRandomData = new byte[1048576];
	
	private byte[] trivialZeroData = new byte[1];
	private byte[] perfectZeroData = new byte[16];
	private byte[] smallZeroData = new byte[51];
	private byte[] bigZeroData = new byte[1048576];
	
	private static int smallThreshold = 2;
	private static int midThreshold = 5;
	private static int bigThreshold = 10;
	
	private static int smallShareCount = 2;
	private static int midShareCount = 5;
	private static int bigShareCount = 10;
	private static int insaneShareCount = 100;
	
	private static int[][] dealerSettings = new int[][]{
			{smallThreshold, smallShareCount},
			{midThreshold, midShareCount},
			{bigThreshold, bigShareCount},
			{smallThreshold, midShareCount},
			{midThreshold, bigShareCount},
			{midThreshold, insaneShareCount}
	};
	
	private byte[][] dataValues;
	
	private String randomPassPhrase;
	private String nullPassPhrase;
 	
	@Before
	public void setUp() throws Exception
	{
		mRandomNumberGenerator.nextBytes(trivialRandomData);
		mRandomNumberGenerator.nextBytes(smallRandomData);
		mRandomNumberGenerator.nextBytes(perfectRandomData);
		mRandomNumberGenerator.nextBytes(bigRandomData);
		
		byte[] randomPassPhraseBytes = new byte[16];
		mRandomNumberGenerator.nextBytes(randomPassPhraseBytes);
		randomPassPhrase = new String(randomPassPhraseBytes);
		
		nullPassPhrase = null;
		
		dataValues = new byte[][]{
			trivialRandomData,
			perfectRandomData,
			smallRandomData,
			bigRandomData,
			trivialZeroData,
			perfectZeroData,
			smallZeroData,
			bigZeroData
		};
	}
	
	@Test
	public void CanInstantiateWithoutPassword()
	{
		Dealer dealer = new Dealer(smallThreshold, smallShareCount);
		assertNotNull(dealer);
	}
	
	@Test
	public void CanInstantiateWithNullPassword()
	{
		Dealer dealer = new Dealer(smallThreshold, smallShareCount, nullPassPhrase);
		assertNotNull(dealer);
	}
	
	@Test
	public void CanInstantiateWithPassword()
	{
		Dealer dealer = new Dealer(smallThreshold, smallShareCount, randomPassPhrase);
		assertNotNull(dealer);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void CannotInstantiateWithTooSmallThreshold()
	{
		new Dealer(0, smallShareCount);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void CannotInstantiateWithShareCountSmallerThanThreshold()
	{
		new Dealer(smallThreshold, smallThreshold - 1);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void CannotInstantiateWithTooSmallShareCount()
	{
		new Dealer(smallThreshold, 1);
	}

	@Test
	public void CanJoinSecrets() throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidKeySpecException, CryptoException
	{
		for(int i = 0; i < dealerSettings.length; ++i)
		{
			int threshold = dealerSettings[i][0];
			int shareCount = dealerSettings[i][1];
			Dealer dealer = new Dealer(threshold, shareCount, randomPassPhrase);
			
			for(int j = 0; j < dataValues.length; ++j)
			{
				byte[] data = dataValues[j];
				
				ShareHolder[] shareHolder = dealer.SplitByteArray(data);
				
				assertEquals(shareCount, shareHolder.length);
				
				byte[] secret = dealer.JoinByteArray(shareHolder);
				
				assertArrayEquals(data, secret);
			}
		}
	}
	
	/*@Test
	public void CanJoinInsaneSecrets() throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidKeySpecException, CryptoException
	{
		Dealer dealer = new Dealer(insaneThreshold, insaneShareCount, randomPassPhrase);
			
		ArrayList<ShareHolder> shareHolder = dealer.SplitByteArray(bigRandomData);
		
		assertEquals(insaneShareCount, shareHolder.size());
		
		byte[] secret = dealer.JoinByteArray(shareHolder);
		
		assertArrayEquals(bigRandomData, secret);
	}*/
}
