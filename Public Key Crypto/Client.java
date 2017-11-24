

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.util.Random;

/**
 * This class is a secure file transfer client.  Connects to the server and sends a
 * file across.
 *
 * @author Pujan Bhatta
 * @version 1.0
 */
public class Client 
{
    private boolean debug;
    private Socket sock;         //Socket to communicate with
    private BufferedReader stdIn;   // for user input
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKeySpec key;   // AES encryption key
    private BigInteger a;
    private BigInteger p;
    private BigInteger ga;
    private BigInteger gb;
    private BigInteger gab;
    private BigInteger g;
    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug) 
	    System.out.println("Debug Client: " + s);
    }




    /**
     * Constructor, in this case does everything.
     * @param ipaddress The hostname to connect to.
     * @param port The port to connect to.
     */
    public Client (String ipaddress, int port, boolean setDebug)
    {
	// set the debug flag
	debug = setDebug;

	// open reader for usesr input
	stdIn = new BufferedReader(new InputStreamReader(System.in));

	// Try to connect to the specified host on the specified port.
	try {
	    sock = new Socket (InetAddress.getByName(ipaddress), port);
	}
	catch (UnknownHostException e) {
	    System.out.println ("Usage: java Client hostname port#");
	    System.out.println ("First argument is not a valid hostname");
	    return;
	}
	catch (IOException e) {
	    System.out.println ("Could not connect to " + ipaddress + ".");
	    return;
	}
		
	// Status info
	System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);



 	// open input and output streams for file transfer
	in = null;
	out = null;
	try {
	    in = new DataInputStream(sock.getInputStream());
	    out = new DataOutputStream(sock.getOutputStream());
	}
	catch (UnknownHostException e) {
	    System.out.println ("Unknown host error.");
	    close();
	}
	catch (IOException e) {
	    System.out.println ("Could not create output stream.");
	    close();
	}
    }




    /**
     * Prompts user for a sting to be used as seed for deriving the AES key
     */
    public void getKey() {
	debug("Getting prime from Server");
	
        try{
            p = new BigInteger(CryptoUtilities.receive(in));
        }
        catch(IOException e){
            System.out.println("Error receiving p");

        }
        
        try{
            g = new BigInteger(CryptoUtilities.receive(in));
        }
        catch(IOException e){
            System.out.println("Error Receiving g");

        }
        debug("Calculating key");
        
        a = new BigInteger(p.subtract(BigInteger.valueOf(2)).bitLength(), new Random());
	
		ga = g.modPow(a, p);
        
        try{
    		CryptoUtilities.send(ga.toByteArray(), out);
    	}
    	catch(IOException e){
    		System.out.println("Error Sending ga");
    		
    	}
        
        try{
            gb = new BigInteger(CryptoUtilities.receive(in));
        }
        catch(IOException e){
            System.out.println("Error recieving gb");

        }
        
        gab = gb.modPow(a, p);
        
	
	// compute key:  1st 16 bytes of SHA-1 hash of seed
	key = CryptoUtilities.key_from_seed(gab.toByteArray());
 	debug("Using key = " + CryptoUtilities.toHexString(key.getEncoded()));
    }




    /**
     * Encrypted file transfer
     * @return true if file transfer was successful
     */
    public boolean sendFile() {
	debug("Starting File Transfer");

	// get input file name
	String infilename;
	FileInputStream infile;
	try {
	    System.out.print("Please enter the source filename: ");
	    infilename = stdIn.readLine();
	    infile = new FileInputStream(infilename);
	}
	catch (IOException e) {
	    System.out.println ("Could not open source file");
	    close();
	    return false;
	}


	// get output file name
	String outfilename;
	try {
	    System.out.print("Please enter the destination filename: ");
	    outfilename = stdIn.readLine();
	}
	catch (IOException e) {
	    System.out.println("Error getting destination filename.");
	    close();
	    return false;
	}

	// send the output file name
	try {
	    debug("Sending output file name = " + outfilename);
	    CryptoUtilities.encryptAndSend(outfilename.getBytes(),key,out);
	}
	catch (IOException e) {
	    System.out.println("Error sending the output file name");
	    close();
	    return false;
	}


	// send the file size
	try {
	    debug("Sending file size = " + infile.available());
	    CryptoUtilities.encryptAndSend(String.valueOf(infile.available()).getBytes(), key,out);	
	}
	catch (IOException e) {
	    System.out.println("Error sending the file length");
	    close();
	    return false;

	}


	// append message digest, encrypt, send file
	try {
	    debug("Encrypting and sending file with MAC appended");
	    // read input file into a byte array
	    byte[] msg = new byte[infile.available()];
	    int read_bytes = infile.read(msg);

	    // append HMAC-SHA-1 message digest
	    byte[] hashed_msg = CryptoUtilities.append_hash(msg,key);

	    // encrypt anad send
	    CryptoUtilities.encryptAndSend(hashed_msg,key,out);
	}
	catch (IOException e) {
	    System.out.println("Error sending encrypted file");
	    close();
	    return false;
	}



	// get acknowledgement from server
	boolean transferOK = false;
	try {
	    debug("Waiting for server acknowledgement");
	    String ack = new String(CryptoUtilities.receiveAndDecrypt(key,in));

	    debug("Got acknowledgement = " + ack);
	    if (ack.compareTo("Passed") == 0) {
		System.out.println("File received and verified");
		transferOK = true;
	    }
	    else {
		System.out.println("Error verifying file");
	    }
	}
	catch (IOException e) {
	    System.out.println("Error getting server acknowledgement");
	    close();
	    return transferOK;
	}

	return transferOK;
    }




    /**
     * Shuts down the socket connection
     */
    public void close() {
	// shutdown socket and input reader
	System.out.println("Shutting down client.");
	try {
	    stdIn.close();
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
     * Outputs usage instructions
     */
    public static void printUsage() {
	System.out.println ("Usage: java Client hostname port#");
	System.out.println("     or java Client debug hostname port#");
	System.out.println (" - hostname is a string identifying your server");
	System.out.println (" - port is a positive integer identifying the port to connect to the server");
    }




    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     */
    public static void main (String [] args)
    {
	boolean setDebug = false;

	if (args.length < 2 || args.length > 3) {
	    printUsage();
	    return;
	}

	// check if debug flag is being set
	String ipaddress;
	int port;
	if (args.length == 3) {
	    if (args[2].compareTo("debug") == 0) {
		setDebug = true;
		ipaddress = args[0];
		port = Integer.parseInt(args[1]);
	    }
	    else {
		printUsage();
		return;
	    }
	}
	else {
	    ipaddress = args[0];
	    port = Integer.parseInt(args[1]);
	}


	// initialize client and socket connections
	Client c;
	try {
	    c = new Client (ipaddress, port, setDebug);
	}
	catch (NumberFormatException e) {
	    printUsage();
	    System.out.println ("ERROR:  second argument was not a port number");
	    return;
	}


	// get the encryption key
	c.getKey();


	// do file transfer
	c.sendFile();


	// shut down the client
	c.close();
    }
	
}
