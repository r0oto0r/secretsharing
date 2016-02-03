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
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Before;
import org.junit.Test;

import secret.sharing.Encryptor;

public class EncryptorTest
{
	private byte[] testByteArray1 = new byte[Encryptor.ContainerSize];
	private byte[] testByteArray2 = new byte[Encryptor.ContainerSize];
	private static final SecureRandom mRandomNumberGenerator = new SecureRandom();

	@Before
	public void init()
	{
		mRandomNumberGenerator.nextBytes(testByteArray1);
		mRandomNumberGenerator.nextBytes(testByteArray2);
	}
	
	@Test
	public void CanInit() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		encryptor = new Encryptor(false);
		
		encryptor = new Encryptor("test", true);
		encryptor = new Encryptor("test", false);
		
		encryptor = new Encryptor("", true);
		encryptor = new Encryptor("", false);
		
		encryptor = new Encryptor(new byte[16], new byte[16], new byte[16], true);
		encryptor = new Encryptor(new byte[16], new byte[16], new byte[16], false);
		
		encryptor = new Encryptor("test", new byte[16], new byte[16], new byte[16], true);
		encryptor = new Encryptor("test", new byte[16], new byte[16], new byte[16], false);
		
		encryptor = new Encryptor("", new byte[16], new byte[16], new byte[16], true);
		encryptor = new Encryptor("", new byte[16], new byte[16], new byte[16], false);
		
		assertNotNull(encryptor);
	}
	
	@Test
	public void CanEncrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		byte[] firstBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		assertEquals(Encryptor.ContainerSize, firstBlock.length);
		assertEquals(Encryptor.ContainerSize, secondBlock.length);
	}
	
	@Test
	public void CanCreateHMAC() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		byte[] firstBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		assertEquals(Encryptor.ContainerSize, firstBlock.length);
		assertEquals(Encryptor.ContainerSize, secondBlock.length);
		
		byte[] hmac = encryptor.GetHMAC();
		
		assertEquals(32, hmac.length);
	}

	@Test
	public void CanDecrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = encryptor.GetIV();
		byte[] encSalt = encryptor.GetEncryptionSalt();
		byte[] hmacSalt = encryptor.GetHMACSalt();
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor(iv, encSalt, hmacSalt, false);
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertArrayEquals(testByteArray1, firstDecryptedBlock);
		assertArrayEquals(testByteArray2, secondDecryptedBlock);
		assertArrayEquals(hmac1, hmac2);
	}
	
	@Test
	public void CanDecryptWithPassword() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor("thisisatest", true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = encryptor.GetIV();
		byte[] encSalt = encryptor.GetEncryptionSalt();
		byte[] hmacSalt = encryptor.GetHMACSalt();
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor("thisisatest", iv, encSalt, hmacSalt, false);
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertArrayEquals(testByteArray1, firstDecryptedBlock);
		assertArrayEquals(testByteArray2, secondDecryptedBlock);
		assertArrayEquals(hmac1, hmac2);
	}
	
	@Test
	public void CanNotDecryptWithWrongPassword() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor("thisisatest", true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = encryptor.GetIV();
		byte[] encSalt = encryptor.GetEncryptionSalt();
		byte[] hmacSalt = encryptor.GetHMACSalt();
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor("tsetasisiht", iv, encSalt, hmacSalt, false);
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertFalse(Arrays.equals(testByteArray1, firstDecryptedBlock));
		assertFalse(Arrays.equals(testByteArray2, secondDecryptedBlock));
		assertFalse(Arrays.equals(hmac1, hmac2));
	}

	@Test
	public void CanNotDecryptWithWrongIV() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = new byte[16];
		mRandomNumberGenerator.nextBytes(iv);
		byte[] encSalt = encryptor.GetEncryptionSalt();
		byte[] hmacSalt = encryptor.GetHMACSalt();
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor(iv, encSalt, hmacSalt, false);
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertFalse(Arrays.equals(testByteArray1, firstDecryptedBlock));
		assertFalse(Arrays.equals(testByteArray2, secondDecryptedBlock));
		assertFalse(Arrays.equals(hmac1, hmac2));
	}
	
	@Test
	public void CanNotDecryptWithWrongEncryptionSalt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = encryptor.GetIV();
		byte[] encSalt = new byte[16];
		mRandomNumberGenerator.nextBytes(encSalt);
		byte[] hmacSalt = encryptor.GetHMACSalt();
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor(iv, encSalt, hmacSalt, false);
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertFalse(Arrays.equals(testByteArray1, firstDecryptedBlock));
		assertFalse(Arrays.equals(testByteArray2, secondDecryptedBlock));
		assertFalse(Arrays.equals(hmac1, hmac2));
	}
	
	@Test
	public void CanNotVerifyWithWrongHMACSalt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor(true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = encryptor.GetIV();
		byte[] encSalt = encryptor.GetEncryptionSalt();
		byte[] hmacSalt = new byte[16];
		mRandomNumberGenerator.nextBytes(hmacSalt);
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor(iv, encSalt, hmacSalt, false);
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertArrayEquals(testByteArray1, firstDecryptedBlock);
		assertArrayEquals(testByteArray2, secondDecryptedBlock);
		assertFalse(Arrays.equals(hmac1, hmac2));
	}
	
	@Test
	public void CanDetectAlteredCipher() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, DataLengthException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		Encryptor encryptor = new Encryptor("thisisatest", true);
		byte[] firstEncryptedBlock = encryptor.ProcessDataBlock(testByteArray1);
		byte[] secondEncryptedBlock = encryptor.ProcessDataBlock(testByteArray2);
		
		byte[] iv = encryptor.GetIV();
		byte[] encSalt = encryptor.GetEncryptionSalt();
		byte[] hmacSalt = encryptor.GetHMACSalt();
		
		byte[] hmac1 = encryptor.GetHMAC();
		
		Encryptor encryptor2 = new Encryptor("thisisatest", iv, encSalt, hmacSalt, false);
		
		int randPos = mRandomNumberGenerator.nextInt(Encryptor.ContainerSize);
		byte randValue = (byte) mRandomNumberGenerator.nextInt();
		while(randValue == firstEncryptedBlock[randPos] || randValue == secondEncryptedBlock[randPos])
			randValue = (byte) mRandomNumberGenerator.nextInt();
		firstEncryptedBlock[randPos] = randValue;
		secondEncryptedBlock[randPos] = randValue;
		
		byte[] firstDecryptedBlock = encryptor2.ProcessDataBlock(firstEncryptedBlock);
		byte[] secondDecryptedBlock = encryptor2.ProcessDataBlock(secondEncryptedBlock);
		
		byte[] hmac2 = encryptor2.GetHMAC();
		
		assertFalse(Arrays.equals(testByteArray1, firstDecryptedBlock));
		assertFalse(Arrays.equals(testByteArray2, secondDecryptedBlock));
		assertFalse(Arrays.equals(hmac1, hmac2));
	}
	
	@Test
	public void CanCreateEncryptionHeader() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException, DataLengthException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException
	{
		Encryptor encryptor = new Encryptor(true);
		encryptor.ProcessDataBlock(testByteArray1);
		encryptor.ProcessDataBlock(testByteArray2);
		byte[][] encHeader = encryptor.GetEncryptionHeader();
		
		byte[] iv = encHeader[0];
		
		byte[] encSalt = encHeader[1];
		
		byte[] hmacSalt = encHeader[2];
		
		ByteBuffer buffer = ByteBuffer.allocate(32);
		buffer.put(encHeader[3]);
		buffer.put(encHeader[4]);
		byte[] hmac = buffer.array();
		
		assertArrayEquals(encryptor.GetIV(), iv);
		assertArrayEquals(encryptor.GetEncryptionSalt(), encSalt);
		assertArrayEquals(encryptor.GetHMACSalt(), hmacSalt);
		assertArrayEquals(encryptor.GetHMAC(), hmac);
	}
}
