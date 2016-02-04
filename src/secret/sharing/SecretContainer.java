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
package secret.sharing;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * Class to add some entropy to the data
 * @author Benjamin Weigl
 */
public class SecretContainer
{
	private static SecureRandom mRandomNumberGenerator = new SecureRandom();
	private static final int mHeaderSize = Integer.SIZE / Byte.SIZE + Integer.SIZE / Byte.SIZE;
	
	private SecretContainer() {
	}
	
	/**
	 * Creates the secret container
	 * @param data data to wrap
	 * @return the secret container
	 */
	public static byte[] CreateSecretContainer(byte[] data)
	{
		byte[] containerHeader = createSecretHeader(data.length);
		
		ByteBuffer buffer = ByteBuffer.allocate(containerHeader.length + data.length);
		buffer.put(containerHeader);
		buffer.put(data);
		
		return buffer.array();
	}
	
	/**
	 * Creates the secret header
	 * @param dataLength length of data to wrap
	 * @return an header with padding according to the data length to match encryption container size condition
	 */
	private static byte[] createSecretHeader(int dataLength)
	{
		if(dataLength < 1) throw new IllegalArgumentException("data length must be greater 0");
		int paddingLength = Encryptor.ContainerSize - ((dataLength + mHeaderSize) % Encryptor.ContainerSize);
		ByteBuffer byteBuffer = ByteBuffer.allocate(paddingLength + mHeaderSize);
		byteBuffer.putInt(paddingLength);
		byteBuffer.putInt(dataLength);
		if(paddingLength > 0)
		{
			byte[] padding = new byte[paddingLength];
			mRandomNumberGenerator.nextBytes(padding);
			byteBuffer.put(padding);
		}
		
		byte[] header = byteBuffer.array();
		
		return header;
	}
	
	/**
	 * Removes the secret container and padding bytes
	 * @param secretContainer the data with a valid secret container header
	 * @return the data without the wrapping container
	 */
	public static byte[] RemoveSecretContainer(byte[] secretContainer)
	{
		ByteBuffer buffer = ByteBuffer.allocate(secretContainer.length);
		buffer.put(secretContainer);
		buffer.rewind();
		
		int paddingLength = buffer.getInt();
		
		int dataLength = buffer.getInt();
		
		buffer.position(paddingLength + mHeaderSize);
		
		byte[] secret = new byte[dataLength];
		
		buffer.get(secret);
		
		return secret;
	}
}
