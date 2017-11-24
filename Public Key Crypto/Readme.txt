Pujan Bhatta
10162769

Compile all of the files using javac *.java
Run the Server with the seed as an argument: java Server <Seed>
Run the Client with 0.0.0.0 as the frist argument and same seed as Server: java Client 0.0.0.0 <Seed>
•A list of the files I have submitted:

	Files: Server.java, ServerThread,java, Client.java, CryptoUtilities.java, Makefile, (this)README

	CryptoUtilities: does the heavy-lifting for the ecryption and decryption of messages
	Server: provide sever services at the specified port number
	ServerThread: generates (P,g) needed for DH, decrypt source file sent by client and place them in the user 	specified file
	Client: connects to and sends encrypted message to server


• A written description of my key exchange protocol including:
	– The protocol is the same as Assignment 2. The only thing different is how I generated the key. I generated p and g in the Server and sent it to client. They both generate their own secret number and calculated g^number (mod p) and share it with each other and then they calculate the recieved value and 		raise it to the power of their secret number (mod p) and they have generated the secret key.
	

I have implemented everything.