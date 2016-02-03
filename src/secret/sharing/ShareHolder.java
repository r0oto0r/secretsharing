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

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Data holder class which holds all shares of a certain index
 * @author Benjamin Weigl
 */
public class ShareHolder implements Serializable
{
	private static final long serialVersionUID = -479177930789689409L;
	private int mIndex = 0;
	private int mThreshold = 0;
	private ArrayList<byte[]> mShares = null;

	/**
	 * Constructor
	 * @param index Equals the x value used to create the shares hold by this shareholder
	 * @param threshold The minimum number of shares required to rebuild the secret
	 */
	public ShareHolder(int index, int threshold)
	{
		if(index < 1) throw new IllegalArgumentException("index must be greater 0");
		mIndex = index;
		if(threshold < 2) throw new IllegalArgumentException("threshold must be greater or equal 2");
		mThreshold = threshold;
		
		mShares = new ArrayList<byte[]>();
	}
	
	/**
	 * Adds a share to the internal array list
	 * @param share share to add
	 */
	public void AddShare(byte[] share)
	{
		mShares.add(share);
	}
	
	public byte[] GetShare(int i)
	{
		return mShares.get(i);
	}
	
	public int GetIndex()
	{
		return mIndex;
	}
	
	public int GetBlockCount()
	{
		return mShares.size();
	}
	
	public int GetThreshold()
	{
		return mThreshold;
	}
	
	/**
	 * Initiates blank share holder for creation purpose
	 * @param shareCount number of shares each shareholder should get
	 * @param threshold minimum number of shareholder required to rebuilt the secret
	 * @return an array of shareholder, size of shareCount
	 */
	public static ShareHolder[] initShareHolder(int shareCount, int threshold)
	{
		ShareHolder[] shareHolder = new ShareHolder[shareCount];
			for(int i = 0; i < shareCount; i++)
				shareHolder[i] = new ShareHolder(i + 1, threshold);
		return shareHolder;
	}
}
