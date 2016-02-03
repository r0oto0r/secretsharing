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

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.BigIntegers;

/**
 * Class that represents a secret sharing dealer
 * @author Benjamin Weigl
 */
public class Dealer
{
	/**
	 * The fixed prime number to define the finite field for all calculations.
	 * The bit size of this prime number is 129, so the container size is set to
	 * 128 bit to ensure any number n less than mPrime
	 */
	private static final BigInteger mPrime = new BigInteger("340282366920938463463374607431768211507");
	/** 
	 * Fixed container size of 128 bit
	 */
	public static final int ContainerSize = 16;
	/**
	 * The minimum number of shares required to rebuild the secret
	 */
	private int mThreshold;
	/**
	 * The number of shares the dealer shall produce
	 */
	private int mShareCount;
	/**
	 * An optional pass phrase for the encryption and integrity check
	 */
	private String mPassPhrase;
	/**
	 * A random polynomial to calculate shares
	 */
	private RandomPolynomial mRandomPolynomial;
	
	/**
	 * Constructor
	 * @param threshold The minimum number of shares required to rebuild the secret
	 * @param shareCount The number of shares the dealer shall produce
	 */
	public Dealer(int threshold, int shareCount)
	{
		this(threshold, shareCount, null);
	}
	
	/**
	 * Constructor
	 * @param threshold The minimum number of shares required to rebuild the secret
	 * @param shareCount The number of shares the dealer shall produce
	 * @param passphrase An optional pass phrase for the encryption and integrity check
	 */
	public Dealer(int threshold, int shareCount, String passphrase)
	{
		if(threshold > shareCount) throw new IllegalArgumentException("threshold has to be smaller or equal to shareCount");
		if(threshold < 2) throw new IllegalArgumentException("threshold has to be greater or equal 2");
		mThreshold = threshold;
		if(shareCount < 2) throw new IllegalArgumentException("shareCount has to be greater or equal 2");
		mShareCount = shareCount;
		
		// if pass phrase is null, the default pass phrase is used by encryption, so no stress here
		mPassPhrase = passphrase;
		
		mRandomPolynomial = new RandomPolynomial(mThreshold - 1, mPrime);
	}
	
	/**
	 * Splits a byte array into shares equal to the predefined shareCount
	 * @param data The byte array of data, that shall be split up into shares
	 * @return A array list of shares ordered by their index
	 */
	public ShareHolder[] SplitByteArray(byte[] data) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidKeySpecException, CryptoException
	{
		byte[] secretContainer = SecretContainer.CreateSecretContainer(data);
		
		byte[][] encryptedDataBlocks = createEncryptedDataBlocks(secretContainer);
		
		ShareHolder[] shareHolder = createShareHolder(encryptedDataBlocks);
		
		return shareHolder;
	}
	
	/**
	 * Join a bunch of shareholder and rebuild the secret
	 * @param shareHolder the array of shareholder
	 * @return the calculated secret
	 */
	public byte[] JoinByteArray(ShareHolder[] shareHolder) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidKeySpecException, CryptoException
	{
		if(shareHolder.length < shareHolder[0].GetThreshold())
			throw new IllegalArgumentException("Not enough shares: This secret needs at least " + shareHolder[0].GetThreshold() + " shares");
		
		byte[][] encryptedDataBlocks = rebuildSecretDataBlocks(shareHolder);
		
		byte[] secretContainer = decryptEncryptedDataBlocks(encryptedDataBlocks);
		
		byte[] secret = SecretContainer.RemoveSecretContainer(secretContainer);
		
        return secret;
	}

	/**
	 * Encrypts a array of byte data
	 * @param data the byte array to encrypt. the data has to be a multiple of the container size
	 * @return a list of encrypted container
	 */
	private byte[][] createEncryptedDataBlocks(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException, DataLengthException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException
	{
		if(data.length % ContainerSize > 0) throw new IllegalArgumentException("data length must be a multiple of " + ContainerSize);
		
		/**
		 * allocate space enough for the data + encryption header
		 */
		byte[][] dataBlocks = new byte[(data.length / ContainerSize) + Encryptor.EncryptionHeaderBlocks][ContainerSize];
		
		Encryptor encryptor = new Encryptor(mPassPhrase, true);
		
		/**
		 * process data put leave space for the encryption header afterwards
		 */
		for(int i = 0, j = Encryptor.EncryptionHeaderBlocks; i < data.length; i += ContainerSize, ++j)
		{
			byte[] currentBlock = new byte[ContainerSize];
			System.arraycopy(data, i, currentBlock, 0, ContainerSize);
			currentBlock = encryptor.ProcessDataBlock(currentBlock);
			dataBlocks[j] = currentBlock;
		}
		
		byte[][] encHeader =  encryptor.GetEncryptionHeader();
		for(int i = 0; i < Encryptor.EncryptionHeaderBlocks; ++i)
			dataBlocks[i] = encHeader[i];
		
		return dataBlocks;
	}
	
	/**
	 * Do the actual magic and create the shares using the encrypted data
	 * @param encryptedDataBlocks a list of encrypted data container
	 * @return an array of shareholder, holding the related shares
	 */
	private ShareHolder[] createShareHolder(byte[][] encryptedDataBlocks)
	{
		ShareHolder[] shareHolder = ShareHolder.initShareHolder(mShareCount, mThreshold);
		
		for(int i = 0; i < encryptedDataBlocks.length; ++i)
		{
			byte[][] curShares = calculateShares(encryptedDataBlocks[i]);
			for(int j = 0; j < mShareCount; ++j)
				shareHolder[j].AddShare(curShares[j]);
		}
		
		return shareHolder;
	}
	
	/**
	 * Calculate the shares using the shamir's secret sharing scheme
	 * @param secretData the actual secret
	 * @return a list of secret shares (sometimes referred as shadows)
	 */
	private byte[][] calculateShares(byte[] secretData)
    {
		BigInteger secret = BigIntegers.fromUnsignedByteArray(secretData);
		
		/**
		 * According to shamir's secret sharing:
		 * f(x) = \sum_{j=0}^{t-1} a_jx^j
		 * share[i] = f(i), i <= 0 <= n
		 */
		byte[][] shares = new byte[mShareCount][];
        for(int x = 0; x < mShareCount; ++x)
        {
        	BigInteger tmpShare = mRandomPolynomial.calculateFunctionValue(secret, BigInteger.valueOf(x + 1));
        	/**
        	 * BigInteger.toByteArray() adds an signing bit to the array. this confuses decryption so we remove this
        	 */
        	byte[] share = BigIntegers.asUnsignedByteArray(tmpShare);
        	shares[x] = share;
        }

        return shares;
    }
	
	/**
	 * Rebuild the secret hidden in the array of shareholder
	 * @param shareHolder a bunch of shareholder which should be related to each other
	 * @return a list of mostly encrypted secret data container
	 */
	private byte[][] rebuildSecretDataBlocks(ShareHolder[] shareHolder)
	{
		int threshold = shareHolder[0].GetThreshold();
		int blockcount = shareHolder[0].GetBlockCount();

		BigInteger[] cFactors = calculateCFactors(threshold, shareHolder);
				
		byte[][] rebuiltSecrets = calculateSecretDataBlocks(cFactors, threshold, blockcount, shareHolder);

		return rebuiltSecrets;
	}
	
	/**
	 * Calculates the c-factors of the Lagrange Interpolation
	 * @param threshold the minimum shares needed to rebuilt the secret, in this case the count of shares uses to rebuilt the secret
	 * @param shareHolder the list of shareholder. here we get our indices
	 * @return an array of c-factors in order of the related shareholder
	 */
	private BigInteger[] calculateCFactors(int threshold, ShareHolder[] shareHolder)
	{
		/**
		 * According to the Lagrange Interpolation:
		 * c_i = \prod\limits_{1 \leq j \leq t, j \neq i} \frac{x_j}{x_j - x_i}~mod~p
		 */
		BigInteger[] cFactors = new BigInteger[threshold];
		for(int i = 0; i < threshold; i++) 
		{
			BigInteger numerator = BigInteger.ONE;
        	BigInteger denominator = BigInteger.ONE;
        	
	        for(int j = 0; j < threshold; j++)
	        {
	            if(j != i)
	            {
	            	BigInteger x_i = BigInteger.valueOf(shareHolder[i].GetIndex());
	            	BigInteger x_j = BigInteger.valueOf(shareHolder[j].GetIndex());
		            numerator = numerator.multiply(x_j).mod(mPrime);
		            denominator = denominator.multiply(x_j.subtract(x_i)).mod(mPrime);
	            }
	        }
	        /**
	         * finite fields allow the product of the modular inverse of a given number instead of the devision
	         */
	        BigInteger inverseDenominator = denominator.modInverse(mPrime);
	        cFactors[i] = numerator.multiply(inverseDenominator).mod(mPrime);
		}
		return cFactors;
	}
	
	/**
	 * Calculates the secret data by Lagrange Interpolation
	 * @param cFactors a list of c-factors (see calculateCFactors)
	 * @param threshold the minimum number of shareholder to use for calculation
	 * @param blockcount the number of secrets in the shareholder
	 * @param shareHolder the list of shareholder
	 * @return the calculated secret in blocks size of container size
	 */
	private byte[][] calculateSecretDataBlocks(BigInteger[] cFactors, int threshold, int blockcount, ShareHolder[] shareHolder)
	{
		byte[][] rebuiltSecrets = new byte[blockcount][];
		/**
		 * Do Lagrange Interpolation for each block
		 */
		for(int b = 0; b < blockcount; b++)
		{
			/**
			 * According to the Lagrange Interpolation:
			 * S = \sum_{i=1}^{t} c_iy_i~mod~p
			 */
			BigInteger secret = BigInteger.ZERO;
			for(int i = 0; i < threshold; i++)
			{
		        BigInteger shareValue = BigIntegers.fromUnsignedByteArray(shareHolder[i].GetShare(b));
		        secret = secret.add(shareValue.multiply(cFactors[i]).mod(mPrime)).mod(mPrime);
		    }
			
			byte[] secretBytes = BigIntegers.asUnsignedByteArray(ContainerSize, secret);			
			rebuiltSecrets[b] = secretBytes;
		}	
		
		return rebuiltSecrets;
	}
	
	/**
	 * Decrypts a set of data blocks and joins the data back to the secret
	 * @param encryptedDataBlocks the encrypted data blocks
	 * @return the decrypted secret
	 */
	private byte[] decryptEncryptedDataBlocks(byte[][] encryptedDataBlocks) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException, InvalidKeySpecException
	{
		if(encryptedDataBlocks.length <  Encryptor.EncryptionHeaderBlocks + 1) throw new IllegalArgumentException("there have to be at least two encrypted data blocks: 1 * header + n * data, n > 0");
		// allocate buffer: number of encrypted data blocks minus 1 (header) times default container size
		ByteBuffer dataBuffer = ByteBuffer.allocate((encryptedDataBlocks.length - Encryptor.EncryptionHeaderBlocks) * ContainerSize);
		
		byte[][] encHeader = new byte[Encryptor.EncryptionHeaderBlocks][];
		for(int i = 0; i < Encryptor.EncryptionHeaderBlocks; ++i)
			encHeader[i] = encryptedDataBlocks[i];
		Encryptor encryptor = new Encryptor(mPassPhrase, false, encHeader);
		
		for(int i = Encryptor.EncryptionHeaderBlocks; i < encryptedDataBlocks.length; ++i)
		{
			byte[] currentBlock = encryptor.ProcessDataBlock(encryptedDataBlocks[i]);
			dataBuffer.put(currentBlock);
		}
		
		if(!encryptor.IsHMACValid()) throw new InvalidCipherTextException("Invalid HMAC!");
		
		return dataBuffer.array();
	}
}
