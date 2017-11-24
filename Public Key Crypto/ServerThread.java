import java.net.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.util.Random;
/**
 * This class represents a thread to deal with clients who connect to Server.  
 * Put what you want the thread to do in it's run() method.
 *
 * @author Pujan Bhatta
 * @version 1.0
 */
public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
    private int idnum;  //The client's id number.
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKeySpec key;   // AES encryption key

    private BigInteger q;
    private BigInteger p;
    private BigInteger g;
    private BigInteger ga;
    private BigInteger gb;
    private BigInteger gba;
    private BigInteger b;

    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(parent.getDebug()) 
	    System.out.println("Debug Server: " + s);
    }



    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server p, int id)
    {
	parent = p;
	sock = s;
	idnum = id;
	in = null;
	out = null;
    }


	
    /**
     * Getter for id number.
     * @return ID Number
     */
    public int getID ()
    {
	return idnum;
    }


	
    /**
     * Getter for the socket, this way the parent thread can
     * access the socket and close it, causing the thread to
     * stop blocking on IO operations and see that the server's
     * shutdown flag is true and terminate.
     * @return The Socket.
     */
    public Socket getSocket ()
    {
	return sock;
    }



    /**
     * Prompts user for a sting to be used as seed for deriving the AES key
     */
    public void getKey() {
        debug("Generating random prime");
    	do{
    		q = new BigInteger(CryptoUtilities.PRIME_BIT_SIZE, new Random());
    		p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(1));
			
    	}while(p.isProbablePrime(3));
    	debug("Sending the prime number prime");
    	try{
    		CryptoUtilities.send(p.toByteArray(), out);
    	}
    	catch(IOException e){
    		System.out.println("Error Sending p");
    		
    	}
        debug("finding primitive root");
    	g = BigInteger.valueOf(1);
    	boolean isPrimitive = false;
        while(isPrimitive != true){
            if(g.modPow(q, p).compareTo(BigInteger.valueOf(1)) != 0){
                isPrimitive = true;
            }
            else{
                g = g.add(BigInteger.valueOf(1));
                if(g.compareTo(p.subtract(BigInteger.valueOf(2))) == 0){
                    System.out.println("Couldn't find a primitive root");
                        System.exit(0);
                }
            }
			
            
        }
		System.out.println("a");
        debug("Sending g");
        try{
    		CryptoUtilities.send(g.toByteArray(), out);
    	}
    	catch(IOException e){
    		System.out.println("Error Sending g");
    		
    	}
        System.out.println("b");
        debug("calculating the key");
        b = new BigInteger(p.subtract(BigInteger.valueOf(2)).bitLength(), new Random());
        gb = g.modPow(b, p);

        try{
            ga = new BigInteger(CryptoUtilities.receive(in));
        }
        catch(IOException e){
            System.out.println("Error recieving ga");

        }
		System.out.println("c");
        try{
            CryptoUtilities.send(gb.toByteArray(), out);
    	}
    	catch(IOException e){
            System.out.println("Error Sending gb");
    		
    	}
		System.out.println("d");
        gba = ga.modPow(b, p);
        key = CryptoUtilities.key_from_seed(gba.toByteArray());
		debug("Using key = " + CryptoUtilities.toHexString(key.getEncoded()));
		System.out.println("e");
    }
        
    /**
     * Encrypted file transfer
     * @return true if file transfer was successful
     */
    public boolean receiveFile() {
	debug("Starting File Transfer");

	// get the output file name
	String outfilename;
	try {
	    debug("Receiving output file name");
	    outfilename = new String(CryptoUtilities.receiveAndDecrypt(key,in));
	    debug("Got file name = " + outfilename);
	}
	catch (IOException e) {
	    System.out.println("Error receiving the output file name");
	    close();
	    return false;
	}

	System.out.println("Output file: " + outfilename);



	// get the file size
	int size;
	try {
	    debug("Receiving file size");
	    size = Integer.parseInt(new String(CryptoUtilities.receiveAndDecrypt(key,in)));	
	    debug("Got file size = " + size);
	}
	catch (IOException e) {
	    System.out.println("Error sending the file length");
	    close();
	    return false;

	}

	System.out.println("File size = " + size);



	// get the encrypted, integrity-protected file
	byte[] hashed_plaintext;
	try {
	    debug("Receiving and decrypting file with MAC appended");
	    hashed_plaintext = CryptoUtilities.receiveAndDecrypt(key,in);
	}
	catch (IOException e) {
	    System.out.println("Error receiving encrypted file");
	    close();
	    return false;
	}


	// check validity of MAC.  Write to the file if valid.
	debug("Checking MAC");
	boolean fileOK = false;
	if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
	    debug("Message digest OK.  Writing file.");
	    System.out.println("Message digest OK. Writing file");

	    // extract plaintext and output to file
	    byte[] plaintext = CryptoUtilities.extract_message(hashed_plaintext);

	    // writing file
	    FileOutputStream outfile = null;
	    try {
		outfile = new FileOutputStream(outfilename);
		outfile.write(plaintext,0,plaintext.length);
		outfile.close();
	    }
	    catch (IOException e) {
		System.out.println("Error writing decrypted file.");
		close();
		return false;
	    }
	    finally {
		try {
		    outfile.close();
		}
		catch (IOException e) {
		    System.out.println("Error closing output file.");
		    return false;
		}
	    }


	    fileOK = true;

	    // send acknowledgement to client
	    try {
		debug("Sending \"passed\" acknowledgement.");
		CryptoUtilities.encryptAndSend("Passed".getBytes(),key,out);
	    }
	    catch (IOException e) {
		System.out.println("Error sending passed acknowledgement.");
		close();
		return true;
	    }

	    System.out.println("File written successfully.");
	}
	else {
	    System.out.println("Integrity check failed.  File not written.");

	    try {
		debug("Sending \"Failed\" acknowledgement.");
		CryptoUtilities.encryptAndSend("Failed".getBytes(),key,out);
	    }
	    catch (IOException e) {
		System.out.println("Error sending failed acknowledgement.");
		close();
		return false;
	    }
	}

	close();
	return fileOK;
    }



    /**
     * Shuts down the socket connection
     */
    public void close() {
	// shutdown socket and input reader
	try {
	    sock.close();
	    if (in != null)
		in.close();
	    if (out != null)
		out.close();
	} 
	catch (IOException e) {
	    return;
	}	
		
    }



	
    /**
     * This is what the thread does as it executes.  Gets the encryption key,
     * receives a file from the client, and shuts down.
     */
    public void run ()
    {
	// open input and output streams for file transfer
	try {
	    in = new DataInputStream(sock.getInputStream());
	    out = new DataOutputStream(sock.getOutputStream());
	}
	catch (UnknownHostException e) {
	    System.out.println ("Unknown host error.");
	    close();
	    return;
	}
	catch (IOException e) {
	    System.out.println ("Could not create input and output streams.");
	    close();
	    return;
	}

	// get the encryption key
	getKey();

	// do file transfer
	receiveFile();

	// shut down the client and kill the server
	close();
	parent.killall();
    }
}
