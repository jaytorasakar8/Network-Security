Name: Jay R Torasakar
SBU ID: 111406252

Homework 3: Plugboard Proxy
-----------------------------------------------------------------------------------------

About Plugboard Proxy:
1. Pbproxy has two modes viz client and server mode. The program can be run in either mode by changing the command line arguments.
2. Instead of connecting directly to the service, clients connect to pbproxy-c service on their machine which connects to the pbproxy-s service running on the same server where the target service runs
3.The pbproxy-c service on the client side encrypts the message using a symmetric key, entered by the user when invoking the pbproxy service on the client side. The messages are taken directly from STDIN.
4.The encrypted message is then relayed to the pbproxy-s. Before relaying the traffic to the target service, pbproxy-s always decrypts it using a static symmetric key. This symmetric key is entered during invoking the pbproxy-s service on the server by the server admin.
5.The program used buffer size of 4096 bytes
6.The program used AES ctr128 mode for encryption and decryption services. 

-----------------------------------------------------------------------------------------
Command line execution:

Our Given pbproxy is a client as well as server side proxy having 2 modes of execution, and can be selected by entereing 2 different command line arguments on the same file.

	pbproxy [-l port] -k keyfile destination port
	
	-l Reverse-proxy mode: listen for inbound connections on <port>
	
	Destination port relays received messages to <destination>:<port>
	
	-k use symmetric key = <keyfile>

Example:
server:
	nc -l -p 5002
pbproxy-s:
	./pbproxy -l 5001 -k 12345 localhost 5002
pbproxy-c
	./pbproxy -k 12345 localhost 5001



-------------------------------------------------------------------------------
References: 
1. http://www.cas.mcmaster.ca/~qiao/courses/cs3mh3/tutorials/socket.html
2. http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html
3. https://www.tutorialspoint.com/unix_sockets/socket_structures.htm
4. http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
5. https://stackoverflow.com/questions/29441005/aes-ctr-encryption-and-decryption
6. https://stackoverflow.com/questions/174531/easiest-way-to-get-files-contents-in-c
7. http://www.thegeekstuff.com/2011/12/c-socket-programming/?utm_source=feedburner
8. http://www.unixmen.com/play-with-netcat-in-ubuntu/
9. http://unix.stackexchange.com/questions/247074/ssh-protocol-mismatch
10.http://www.firmcodes.com/how-do-aes-128-bit-cbc-mode-encryption-c-programming-code-openssl/