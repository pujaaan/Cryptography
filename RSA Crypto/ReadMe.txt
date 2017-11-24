Pujan Bhatta
10162769

Compile all of the files using javac *.java
Run the Server with the seed as an argument: java Server <Seed>
Run the Client with 0.0.0.0 as the frist argument and same seed as Server: java Client 0.0.0.0 <Seed>
•A list of the files I have submitted:

	Files: Server.java, ServerThread,java, Client.java, CryptoUtilities.java, RSAtool.java, ReadMe.txt

	CryptoUtilities: Contains useful functions for encryption, decryption and many more
	Server: provide sever services at the specified port number
	ServerThread: generates (P,g) needed for DH, decrypt source file sent by client and place them in the user specified file
	Client: connects to and sends encrypted message to server
	RSATool: Generates public key (n,e) needed for RSA OAEP, encrypt and decrypt the given byte[]

Everything is implemented and there are no bugs.

Parameters:
p and q: They are both 512 bit randomly generated safe prime. They are in a form 2m + 1 where m is also a prime. Safe prime are crpytographically secure for large primes 
n = p * q, phi(n) = (p-1)(q-1)
e : e starts from 3 but if gcd(e, phi(n)) != 1 then e = e+2 and we check it again until gcd(e, phi(n)) = 1
d = inverse(e) mod n-1
