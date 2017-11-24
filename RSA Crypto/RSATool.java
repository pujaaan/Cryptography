import java.io.*;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @author Mike Jacobson
 * @version 1.0, October 23, 2013
 */

// CRT Reference - http://www.di-mgt.com.au/crt_rsa.html
// https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
public class RSATool {
    // OAEP constants
    private final static int K = 128;   // size of RSA modulus in bytes
    private final static int K0 = 16;  // K0 in bytes
    private final static int K1 = 16;  // K1 in bytes

    // RSA key data
    private BigInteger n;
    private BigInteger e, d, p, q;

    // TODO:  add whatever additional variables that are required to implement 
    //    Chinese Remainder decryption as described in Problem 2
    private BigInteger dP,dQ,qInv, m1, m2, h;
    
    // SecureRandom for OAEP and key generation
    private SecureRandom rnd;

    private boolean debug = false;



    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug) 
	    System.out.println("Debug RSA: " + s);
    }


    /**
     * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
     */
    private byte[] G(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}


	byte[] output = new byte[K-K0];
	byte[] input = M;

	int numBytes = 0;
	while (numBytes < K-K0) {
          byte[] hashval = sha1.digest(input);

	  if (numBytes + 20 < K-K0)
	      System.arraycopy(hashval,0,output,numBytes,K0);
	  else
	      System.arraycopy(hashval,0,output,numBytes,K-K0-numBytes);

	  numBytes += 20;
	  input = hashval;
	}

	return output;
    }



    /**
     * H(M) = the 1st K0 bytes of SHA1(M)
     */
    private byte[] H(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}

        byte[] hashval = sha1.digest(M);
 
	byte[] output = new byte[K0];
	System.arraycopy(hashval,0,output,0,K0);

	return output;
    }



    /**
     * Construct instance for decryption.  Generates both public and private key data.
     *
     * TODO: implement key generation for RSA as per the description in your write-up.
     *   Include whatever extra data is required to implement Chinese Remainder
     *   decryption as described in Problem 2.
     */
    public RSATool(boolean setDebug) {
	// set the debug flag
	debug = setDebug;
        
	rnd = new SecureRandom();
        
        debug("Generating Variables");
	// TODO:  include key generation implementation here (remove init of d)
        
        // Generating strong primes q and q
        do{
            p = BigInteger.probablePrime(4*K, rnd);
            p = p.multiply(BigInteger.valueOf(2));
	    p = p.add(BigInteger.ONE);
        } while(!p.isProbablePrime(CryptoUtilities.CERTAINTY));
        debug("p = " + p);
        do{
            q = BigInteger.probablePrime(4*K, rnd);
            q = q.multiply(BigInteger.valueOf(2));
	    q = q.add(BigInteger.ONE);
        } while(!q.isProbablePrime(CryptoUtilities.CERTAINTY));
        debug("q = "  + q);
        // n = pq
        
        n = p.multiply(q);
        debug("n = " + n);
        
        // phi(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        debug("phi = " + phi);
        
        e = BigInteger.valueOf(3);
        do{
            while(e.gcd(phi).compareTo(BigInteger.ONE) != 0){
                e = e.add(BigInteger.valueOf(2));
            }
             debug("e = " + e);
            // d = modular inverse of e and phi
            d = e.modInverse(phi);
            debug("d = " + d);
        // repeat until d^4 > n to prevent the Boneh/Durfee attack
        }while(d.pow(4).compareTo(n) == -1);
        
        // CRT Decryption
	dP = d.mod(p.subtract(BigInteger.ONE));
        debug("d mod p-1 = " + dP);
	dQ = d.mod(q.subtract(BigInteger.ONE));
        debug("d mod q-1 = " + dQ);
        qInv = q.modInverse(p);
        debug("q^-1 mod p = " + qInv);
    }


    /**
     * Construct instance for encryption, with n and e supplied as parameters.  No
     * key generation is performed - assuming that only a public key is loaded
     * for encryption.
     */
    public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
	// set the debug flag
	debug = setDebug;

	// initialize random number generator
	rnd = new SecureRandom();

	n = new_n;
	e = new_e;

	d = p = q = dQ = dP = qInv = m1 = m2 = null;

	// TODO:  initialize RSA decryption variables here
    }



    public BigInteger get_n() {
	return n;
    }

    public BigInteger get_e() {
	return e;
    }



    /**
     * Encrypts the given byte array using RSA-OAEP.
     *
     * TODO: implement RSA encryption
     *
     * @param plaintext  byte array representing the plaintext
     * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1 bytes
     * @return resulting ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
	debug("In RSA encrypt");

	// make sure plaintext fits into one block
	if (plaintext.length > K-K0-K1){
	    throw new IllegalArgumentException("plaintext longer than one block");
        }
	// TODO:  implement RSA-OAEP encryption here (replace following return statement)


        BigInteger C;
        do{
            // Initialize arrays
            byte [] r = new byte[K0];
            byte [] s = new byte [K - K0];
            byte [] t = new byte [K0];
            byte[] st = new byte[K];
            rnd.nextBytes(r);
            debug("r = " + CryptoUtilities.toHexString(r));

            byte [] g_r = G(r);
            debug("G(r) = " + CryptoUtilities.toHexString(g_r));
             
            // s = (M||0^k_1) xor G(r)
            for(int i = 0; i < K-K0; i++){
                if(i < plaintext.length){
                    s[i] = plaintext[i];
                    s[i] ^= g_r[i];
                }
                else{

                    s[i] = 0;
                    s[i] ^= g_r[i];
                }
            }
            debug("s = " + CryptoUtilities.toHexString(s));

            byte [] h_s = H(s);
            debug("H(s) = " + CryptoUtilities.toHexString(h_s));

            for(int i = 0; i < K0; i++){
                t[i] = (byte) (r[i] ^ h_s[i]);
            }

            //(s||t)
            System.arraycopy(s,0,st,0,K-K0);
            System.arraycopy(t,0,st,K-K0,K0);
            debug("(s||t) = " + CryptoUtilities.toHexString(st));
            
            C = new BigInteger(st);
        // If (s||t) is greater than or equal to n 
        // A padding error sometimes occured and debug showed that it was for negative numbers 
        // So we find a new C if its negative
        }while (C.compareTo(n) >= 0 || C.compareTo(BigInteger.ZERO) == -1);
        C = C.modPow(e, n);
        debug("C = " + C);
        
	return C.toByteArray();
    }


    /**
     * Decrypts the given byte array using RSA.
     *
     * TODO:  implement RSA-OAEP decryption using the Chinese Remainder method described in Problem 2
     *
     * @param ciphertext  byte array representing the ciphertext
     * @throw IllegalArgumentException if the ciphertext is not valid
     * @throw IllegalStateException if the class is not initialized for decryption
     * @return resulting plaintexttext
     */
    public byte[] decrypt(byte[] ciphertext) {
	debug("In RSA decrypt");

	// make sure class is initialized for decryption
	if (d == null)
	    throw new IllegalStateException("RSA class not initialized for decryption");

	// TODO:  implement RSA-OAEP encryption here (replace following return statement)
        // make sure ciphertext fits into one block

        BigInteger C = new BigInteger(ciphertext);
        debug("C = " + C);
        
        if (C.compareTo(n) >= 0){
	    throw new IllegalArgumentException("ciphertext longer than one block");
        }
        //decrypt using CRT
	m1 = C.modPow(dP, p);
	m2 = C.modPow(dQ, q);
        h = qInv.multiply(m1.subtract(m2)).mod(p);
        
        BigInteger M = m2.add(h.multiply(q));
	debug("M = " + M);
        
        
        // Initialize arrays
        byte[] st = M.toByteArray();
	byte[] s = new byte[K-K0];
	byte[] t = new byte[K0];
        byte[] u = new byte[K0];
        byte[] v = new byte[K-K0];
        
        // copying s
        System.arraycopy(st,0,s,0,K-K0);
	debug("s = " + CryptoUtilities.toHexString(s));
        
        // copying t
        System.arraycopy(st,K-K0,t,0,K0);
	debug("t = " + CryptoUtilities.toHexString(t));
        
         // u = t xor H(s)
        byte[] h_s = H(s);
	debug("H(s) = " + CryptoUtilities.toHexString(h_s));
	for (int i=0; i<K0; i++)
	    u[i] = (byte) (t[i] ^ h_s[i]);
	debug("u = " + CryptoUtilities.toHexString(u));
        
        // v = s xor G(u)
        byte[] g_u = G(u);
	debug("G(u) = " + CryptoUtilities.toHexString(g_u));
	for (int i=0; i<K-K0; i++)
	    v[i] = (byte) (s[i] ^ g_u[i]);
	debug("v = " + CryptoUtilities.toHexString(v));
        
        // Checking the last K0 bits of v to see if they are all 0. 
        for (int i = K-K1-K0; i<K - K0; i++)
	    if (v[i] != 0){
		throw new IllegalArgumentException("Padding error: ciphertext invalid");
        }
        // If v's has correct padding of 0 then we get M
	M = new BigInteger(v);
	debug("M as integer = " + M);

	return M.toByteArray();
    }
}
