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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import org.bouncycastle.util.BigIntegers;

/**
 * Class that represents a random polynomial for share calculation
 * @author r0ot
 *
 */
public class RandomPolynomial
{
	private static SecureRandom mRandomNumberGenerator = new SecureRandom();
    private ArrayList<BigInteger> mCoefficients;
    private BigInteger mPrime;
    
    public RandomPolynomial(int coefficientCount, BigInteger prime)
    {
    	if(coefficientCount < 1) throw new IllegalArgumentException("there has to be at least one coefficient");
    	mPrime = prime;
    	mCoefficients = new ArrayList<BigInteger>();
    	mCoefficients.addAll (createPolynom (coefficientCount));
    }
    
    public BigInteger calculateFunctionValue(BigInteger secret, BigInteger x)
    {
    	for(int i = 0; i < mCoefficients.size(); ++i)
    	{
    		BigInteger xValue = x.modPow(BigInteger.valueOf(i + 1), mPrime);
    		secret = secret.add(mCoefficients.get(i).multiply(xValue).mod(mPrime)).mod(mPrime);
    	}
    	
    	return secret;
    }

    private ArrayList<BigInteger> createPolynom(int coefficientCount)
    {
        ArrayList<BigInteger> temp = new ArrayList<BigInteger> ();
        /**
         *  remember when i == coefficentCount, coefficient_i != 0
         *  Coefficient <= prime - 1
         *  coefficentCount - 1: reduced by one because of the last coefficient != 0 condition
         */
        for (int i = 0; i < coefficientCount - 1; i++)
            temp.add(BigIntegers.createRandomInRange(BigInteger.ZERO, mPrime.subtract(BigInteger.ONE), mRandomNumberGenerator));
        
        temp.add(BigIntegers.createRandomInRange(BigInteger.ONE, mPrime.subtract(BigInteger.ONE), mRandomNumberGenerator));
        
        return temp;
    }
}
