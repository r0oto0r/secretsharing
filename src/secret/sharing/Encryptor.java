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
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Class to encrypt data stream in advance
 * Algorithm used in this class is:
 * AES-128 / CBC + HMAC SHA256
 * Keyfactory:
 * PBKDF2 with HMAC SHA1
 * @author Benjamin Weigl
 */
public class Encryptor
{
	public static final int ContainerSize = 16;
	private static final int mIVSize = 16;
	private static final int mHMACSaltSize = 16;
	private static final int mHMACKeySize = 160; //Bit
	private static final int mEncryptionSaltSize = 16;
	private static final int mHMACSize = 32;
	public static final int EncryptionHeaderSize = mIVSize + mEncryptionSaltSize + mHMACSaltSize + mHMACSize;
	public static final int EncryptionHeaderBlocks = EncryptionHeaderSize / ContainerSize;
	/**
	 * If the user gives no pass phrase, a default pass phrase is used so the encryption at least increases the entropy of the data blocks
	 */
    private static final String mDefaultEncryptionPassphrase = "SecretSharingIsAwesome!";
    private static final int mEncryptionKeySize = 128; //Bit
    private static final int mDefaultKeyDerivationRounds = 10000;
    private static final String mDefaultKeyFactory = "PBKDF2WithHmacSHA1";
	private static final SecureRandom mRandomNumberGenerator = new SecureRandom();
	
	private byte[] mIV = null;
	private byte[] mHMACSalt = null;
	private byte[] mEncryptionSalt = null;
	private byte[] mHMAC = null;
	private byte[] mParsedHMAC = null;
	private String mPassPhrase = null;
	private BufferedBlockCipher mCipher;
	private HMac mHmac;
	private boolean mCipherMode;
	
	/**
	 * Constructor
	 * @param mode True = encrypt; False = decrypt
	 */
	public Encryptor(boolean mode) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		this(null, mode);
	}
	
	/**
	 * Constructor
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param mode True = encrypt; False = decrypt
	 */
	public Encryptor(String passphrase, boolean mode) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		this(passphrase, null, null, null, mode);
	}
	
	/**
	 * Constructor
	 * @param initVector initialization vector for CBC mode
	 * @param encryptionSalt encryption salt for encrytption / decryption key
	 * @param hmacSalt salt for HMAC key
	 * @param mode True = encrypt; False = decrypt
	 */
	public Encryptor(byte[] initVector, byte[] encryptionSalt, byte[] hmacSalt, boolean mode) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		this(null, initVector, encryptionSalt, hmacSalt, mode);
	}
	
	/**
	 * Constructor
	 * @param mode True = encrypt; False = decrypt
	 * @param header encryption header created by this class
	 */
	public Encryptor(boolean mode,  byte[][] header) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		this(null, mode, header);
	}
	
	/**
	 * Constructor
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param mode True = encrypt; False = decrypt
	 * @param header encryption header created by this class
	 */
	public Encryptor(String passphrase, boolean mode, byte[][] header) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		byte[] iv = header[0];
		byte[] encryptionSalt = header[1];
		byte[] hmacSalt = header[2];
		
		mParsedHMAC = new byte[mHMACSize];
		ByteBuffer buffer = ByteBuffer.allocate(mHMACSize);
		buffer.put(header[3]);
		buffer.put(header[4]);
		buffer.rewind();
		buffer.get(mParsedHMAC);
		
		Init(passphrase, iv, encryptionSalt, hmacSalt, mode);
	}
	
	/**
	 * Constructor
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param initVector initialization vector for CBC mode
	 * @param encryptionSalt encryption salt for encrytption / decryption key
	 * @param hmacSalt salt for HMAC key
	 * @param mode True = encrypt; False = decrypt
	 */
	public Encryptor(String passphrase, byte[] initVector, byte[] encryptionSalt, byte[] hmacSalt, boolean mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		Init(passphrase, initVector, encryptionSalt, hmacSalt, mode);
	}
	
	/**
	 * Init this encryptor, checks every parameter on reasonability
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param initVector initialization vector for CBC mode
	 * @param encryptionSalt encryption salt for encrytption / decryption key
	 * @param hmacSalt salt for HMAC key
	 * @param mode True = encrypt; False = decrypt
	 */
	private void Init(String passphrase, byte[] initVector, byte[] encryptionSalt, byte[] hmacSalt, boolean mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException
	{
		if(passphrase == null)
			mPassPhrase = mDefaultEncryptionPassphrase;
		else
			mPassPhrase = passphrase;
		
		if(initVector == null)
			mIV = generateRandom(mIVSize);
		else
		{
			if(initVector.length != mIVSize) throw new IllegalArgumentException("Initiation vector has to be " + mIVSize + " byte");
			mIV = initVector;
		}
		
		if(encryptionSalt == null)
			mEncryptionSalt = generateRandom(mEncryptionSaltSize);
		else
		{
			if(encryptionSalt.length != mEncryptionSaltSize) throw new IllegalArgumentException("Encryption key salt has to be " + mEncryptionSaltSize + " byte");
			mEncryptionSalt = encryptionSalt;
		}
		
		if(hmacSalt == null)
			mHMACSalt = generateRandom(mHMACSaltSize);
		else
		{
			if(hmacSalt.length != mHMACSaltSize) throw new IllegalArgumentException("HMAC key salt has to be " + mHMACSaltSize + " byte");
			mHMACSalt = hmacSalt;
		}
		
		mCipherMode = mode;
		
		initCipher(mPassPhrase, mEncryptionSalt, mIV, mCipherMode);
		initHMAC(mPassPhrase, mHMACSalt);
	}
	
	/**
	 * Initiate the block cipher
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param encryptionSalt encryption salt for encrytption / decryption key
	 * @param initVector initialization vector for CBC mode
	 * @param mode True = encrypt; False = decrypt
	 */
	private void initCipher(String passphrase, byte[] encryptionSalt, byte[] initVector, boolean mode) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(new AESFastEngine());
		mCipher = new BufferedBlockCipher(cbcBlockCipher);
		byte[] encryptionKey = deriveKey(passphrase, encryptionSalt, mEncryptionKeySize);
		ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(encryptionKey), initVector);
		mCipher.init(mode, parameters);
	}
	
	/**
	 * Initiate the HMAC generator
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param hmacSalt salt for HMAC key
	 */
	private void initHMAC(String passphrase, byte[] hmacSalt) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		byte[] hmacKey = deriveKey(passphrase, hmacSalt, mHMACKeySize);
		mHmac = new HMac(new SHA256Digest());
		mHmac.init(new KeyParameter(hmacKey));
		mHMAC = null;
	}
	
	/**
	 * Used to create random IVs, salts etc.
	 * @param length length of random byte array
	 * @return byte array of requested length filled with random bytes provided by SecureRandom
	 */
	private byte[] generateRandom(int length)
	{
		byte[] random = new byte[length];
		mRandomNumberGenerator.nextBytes(random);
		return random;
	}
	
	/**
	 * Process one data block of container size
	 * @param data data to encrypt or decrypt
	 * @return encrypted / decrypted data block
	 */
	public byte[] ProcessDataBlock(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException
	{
		checkDataLength(data);
		byte[] processedBytes = new byte[ContainerSize];
		
		int len = mCipher.processBytes(data, 0, data.length, processedBytes, 0);
		mCipher.doFinal(processedBytes, len);
		
		mHmac.update(mCipherMode ? data : processedBytes, 0, ContainerSize);
		
		return processedBytes;
	}
	
	/**
	 * Checks if given data array is in bounds
	 * @param data data to check
	 */
	private void checkDataLength(byte[] data)
	{
		if(data.length != ContainerSize) throw new IllegalArgumentException("data length is " + data.length + " byte but has to be " + ContainerSize + " byte");
	}

	/**
	 * Uses the SecretKeyFactory to derive encryption / decryption keys
	 * @param passphrase string used for encryption / decryption and authentification
	 * @param salt for key
	 * @param keySize well, the size of the key
	 * @return derived key bytes
	 */
	private byte[] deriveKey(String passphrase, byte[] salt, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException
	{  
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(mDefaultKeyFactory);
	    KeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), salt, mDefaultKeyDerivationRounds, keySize);
	    Key key = secretKeyFactory.generateSecret(keySpec);
	    
	    return key.getEncoded();
	}
	
	public byte[] GetIV()
	{
		return mIV.clone();
	}
	
	public byte[] GetEncryptionSalt()
	{
		return mEncryptionSalt.clone();
	}
	
	public byte[] GetHMACSalt()
	{
		return mHMACSalt.clone();
	}
	
	public byte[] GetHMAC()
	{
		if(mHMAC == null)
		{
			mHMAC = new byte[mHMACSize];
			mHmac.doFinal(mHMAC, 0);
		}
		
		return mHMAC;
	}
	
	/**
	 * Creates and returns the encryption header
	 * @return encryption header
	 */
	public byte[][] GetEncryptionHeader()
	{
		byte[][] header = new byte[EncryptionHeaderBlocks][ContainerSize];
		header[0] = GetIV();
		header[1] = GetEncryptionSalt();
		header[2] = GetHMACSalt();
		byte[] hmac = GetHMAC();
		ByteBuffer buffer = ByteBuffer.allocate(hmac.length);
		buffer.put(hmac);
		buffer.rewind();
		buffer.get(header[3]);
		buffer.get(header[4]);
		
		return header;
	}
	
	/**
	 * Checks if HMAC provided by the encryption header is equally with the calculated HMAC
	 * @return True if both are equal, otherwise false
	 */
	public boolean IsHMACValid()
	{
		byte[] curHMAC = GetHMAC();
		if(curHMAC != null && mParsedHMAC != null)
			return Arrays.areEqual(curHMAC, mParsedHMAC);
		return false;
	}
}