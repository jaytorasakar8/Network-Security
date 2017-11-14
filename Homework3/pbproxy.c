#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>

void *write1(void *ptr);
void *write2(void *ptr);
void *read1(void *ptr);
void *read2(void *ptr);
void start_processing (int sock,char *server_ip, char *d_port, char *keyfile);
int client_mode(char *server_ip, char *portno, char *keyfile);
int server_mode( char *port,char *server_ip, char *d_port, char *keyfile);
void encrypt_function(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv);
void decrypt_function(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv);
int setNonblocking(int fd);


struct struct_temp
{
	int sockfd;
	int sock;
	char* keyfile;
};

struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

AES_KEY key; 
struct ctr_state state;	 


int client_mode(char *server_ip, char *d_port, char *keyfile) 
{
	int sockfd;
	int portno;
	int n;

	struct sockaddr_in server_addr;
	struct hostent *server;
	char *str=NULL;
	struct struct_temp *ptr = NULL;
	pthread_t rthread, wthread;
	int  iret1, iret2;
	char buffer[4096];
	portno = atoi(d_port);

	/* Create a socket point */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
	if (sockfd < 0)
	{
		perror("\nError in socket initialization");
		exit(1);
	}

	server = gethostbyname(server_ip);
	if (server == NULL) 
	{
		fprintf(stderr,"\n Error");
		exit(0);
	}

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
	server_addr.sin_port = htons(portno);

	/* Making a connection to the server */
	if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) 
	{
		perror("Connection Erro");
		exit(1);
	}

   	ptr = (struct struct_temp*)malloc(sizeof(struct struct_temp));
	ptr->sock =0;
	ptr->sockfd=sockfd;
	ptr->keyfile = keyfile;

	iret1 = pthread_create( &wthread, NULL, write1, (void*)ptr);
	iret2 = pthread_create( &rthread, NULL, read1, (void*)ptr);
	
	pthread_join( wthread, NULL);
	pthread_join( rthread, NULL);
	close(sockfd);
	return 0;
}

int server_mode( char *port,char *server_ip, char *d_port, char *keyfile) 
{
	int sockfd, portno, client_len;
	char buffer[4096];
	struct sockaddr_in server_addr, client_addr;
	int n, pid;
	int  newsockfd;

	/* Call to socket() */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	/* Initialize socket structure */
	bzero((char *) &server_addr, sizeof(server_addr));
	
	//portno = 5001 port
	portno = atoi(port);//pbproxy server port

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) 
	{
		perror("ERROR on binding");
		exit(1);
	}

	listen(sockfd,5); //Listen on socketfd
	client_len = sizeof(client_addr);
   
	while (1) 
	{
		newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &client_len);

		/* Create child process */
		pid = fork();
		if (pid < 0) 
		{
			perror("ERROR on fork");
			exit(1);
		}
		if (pid == 0)
		 {
			close(sockfd);
			start_processing(newsockfd,server_ip, d_port, keyfile);
			exit(0);
		}
		else 
		{
			close(newsockfd);
		}

	} 
}

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

void encrypt_function(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv)
{ 
	int index=0;
	char temp[AES_BLOCK_SIZE];
	int i=0,j=0;
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set encryption key.");
        exit(1); 
    }
	//printf("Enter the text to be encrypted :");
	//fgets(in_data,1023,stdin);
	init_ctr(&state, iv); //Counter call
	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext	
	for(i=0;in_data[i]!= '\0';i++)	
	{
		for(j=0;j<AES_BLOCK_SIZE && in_data[i]!='\0';j++)
		{
			temp[j]=in_data[i];
			i++;
		}
		i--;
		AES_ctr128_encrypt(temp, out_data+index, j , &key, state.ivec, state.ecount, &state.num);
		index+=j;
		if (j < AES_BLOCK_SIZE)
		{
			break;
		}
	}
}


void decrypt_function(char* in_data, char* out_data, const unsigned char* enc_key, unsigned char *iv)
{	
	
	int index=0;
	char temp[AES_BLOCK_SIZE];
	int i=0,j=0;
	//Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set decryption key.");
        exit(1);
    }
	init_ctr(&state, iv);//Counter call
	
	for(i=0;in_data[i]!= '\0';i++)	
	{
		for(j=0;j<AES_BLOCK_SIZE && in_data[i]!='\0';j++)
		{
			temp[j]=in_data[i];
			i++;
		}
		i--;
		AES_ctr128_encrypt(temp, out_data+index, j, &key, state.ivec, state.ecount, &state.num);
        index+=j; 
		if (j < AES_BLOCK_SIZE) 
			break;
		
	} 
}

void *write1( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
	struct struct_temp *temp = (struct struct_temp*)ptr;
	int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096]; //Buffer Size problem: Checking different values
	char *str=NULL;
	int n=0;

	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);    
	}

	n = write(sockfd, iv, AES_BLOCK_SIZE);
	if (n <= 0) {
		perror("Error writing to socket");
		close(sockfd);
		free(str);
		exit(1);
	}
	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		//fgets(buffer,4095,stdin);
		read(STDIN_FILENO, buffer, 4096);
		if(strlen(buffer) > 0)
		{
			encrypt_function(buffer,str,(unsigned const char*)keyfile, iv);
			//printf("\n Encrypted message: %s\n",str);
			
			/* Send message to the server */
			n = write(sockfd, str, strlen(buffer));
			
			/*Error handling optional */
			if (n <= 0)
			{
				perror("Error in socket");
				close(sockfd);
				free(str);
				exit(1);
			}
		}
	}
	free(str);
}

void *read1( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
    struct struct_temp *temp = (struct struct_temp*)ptr;
    int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;
	n = read(sockfd, iv, AES_BLOCK_SIZE);
	if (n <= 0)
	{
		perror("Error from socket");
		close(sockfd);
		free(str);
		exit(1);
	}
	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		n = read(sockfd, buffer, 4096);
		
		/*Error handling */
		/*if (n <= 0) 
		{
			perror("Erro from socket");
			close(sockfd);
			free(str);
			exit(1);
		}*/

		printf("Encrypted text(received from pbproxy server): %s \n",buffer);
		decrypt_function(buffer,str,(unsigned const char*)keyfile, iv);
		printf("Decrypted text(received from pbproxy server): ");
		strcat(str,"\0");
		printf("%s",str);

	}
	free(str);
}

void start_processing (int sock,char *server_ip, char *d_port, char *keyfile) 
{
	int sockfd, portno, n;
	struct struct_temp *ptr = NULL;
	struct sockaddr_in server_addr;
	struct hostent *server;
	pthread_t rthread, wthread;
	int  iret1, iret2;

	portno = atoi(d_port);

	/* Create a socket point */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	{
		perror("Error in socket");
		exit(1);
	}

	/*Server handling */ 
	server = gethostbyname(server_ip);
	if (server == NULL) {
		fprintf(stderr,"Error\n");
		exit(0);
	}
	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
	server_addr.sin_port = htons(portno);
   
	/* connect to the server */
	if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		//If connecction problem then show error  and terminate
		perror("Erro connecting");
		exit(1);
	}

	ptr = (struct struct_temp*)malloc(sizeof(struct struct_temp));
	ptr->sock =sock;
	ptr->sockfd=sockfd;
	ptr->keyfile = keyfile;
	iret1 = pthread_create( &wthread, NULL, write2, (void*) ptr);
	if(iret1)
	{
		fprintf(stderr,"Error in pthread_create() : %d\n",iret1);
		exit(EXIT_FAILURE);
	}

	iret2 = pthread_create( &rthread, NULL, read2, (void*) ptr);
	if(iret2)
	{
		fprintf(stderr,"Error in pthread_create() : %d\n",iret2);
		exit(EXIT_FAILURE);
	}
	
	pthread_join( wthread, NULL);
	pthread_join( rthread, NULL);
	free(ptr);
	close(sockfd);
	close(sock);
	return;
}


void *read2( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
	struct struct_temp *temp = (struct struct_temp*)ptr;
    int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;

	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		close(sockfd);
		close(sock);
		exit(1);    
	}

	n = write(sock, iv, AES_BLOCK_SIZE);
	if (n <= 0) 
	{
		close(sockfd);
		close(sock);
		perror("Error in socket");
		free(str);
		exit(1);
		//pthread_exit(NULL);
	}

	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		n = read(sockfd, buffer, 4096);
		if (n <= 0) {
			close(sockfd);
			close(sock);
			perror("Error in socket");
			free(str);
			exit(1);
			//pthread_exit(NULL);
		}

		//printf("\nHere is the response received from server: %s\n",buffer);
		//printf("Encrypting the response\n");
		//strcpy(buffer,"I got your message");
		bzero(str,4096);
		encrypt_function(buffer,str,(unsigned const char*)keyfile, iv);
		//printf("Encrpted message: %s \n",str);
		//printf("Sending the encrypted message back to the pbproxy_client \n");
		n = write(sock,str,strlen(str));
		if (n <= 0) {
			close(sockfd);
			close(sock);
			perror("Error in socket");
			free(str);
			exit(1);
		}
	}
	free(str);
}
void *write2( void *ptr )
{
	unsigned char iv[AES_BLOCK_SIZE];
	struct struct_temp *temp = (struct struct_temp*)ptr;
    int sockfd = temp->sockfd;
	int sock = temp->sock;
	char *keyfile = temp->keyfile;
	char buffer[4096];
	char *str=NULL;
	int n=0;
	n = read(sock, iv, AES_BLOCK_SIZE);
	
	str = (char*)malloc(4096*sizeof(char));
	while(1)
	{
		bzero(buffer,4096);
		bzero(str,4096);
		n = read(sock,buffer,4096);
		
		printf("\nHere is the encrypted message received from pbproxy_client: %s\n",buffer);
		decrypt_function(buffer,str,(unsigned const char*)keyfile, iv);
		printf("Here is the decrypted message: %s\n",str);
		
		//printf("Sent the decrypted message to the server\n");
		//send this message(str) to the server and receive server's response here into buffer
		n = write(sockfd, str, strlen(buffer));
		if (n <= 0) 
		{
			close(sockfd);
			close(sock);
			perror("Error in socket");
			free(str);
			exit(1);
		}
	}
	free(str);
}

int main(int argc, char *argv[]) {
	char *keyfile = NULL;
	char *port = NULL;
	char *dest = NULL;
	char *d_port = NULL;
	int ser_mode=0;
	int has_key = 0;
	char c;
	int index;
	while ((c = getopt (argc, argv, "k:l:")) != -1)
	{
		switch (c)
		{
			case 'l':
				ser_mode = 1;//server mode on
				port = optarg;
				break;
			
			case 'k':
				keyfile = optarg;
				has_key =1;
				break;
			
			/* case '?':
				if (optopt == 'k')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'l')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				return 1;
			*/
			default:
			
				return(0);
				break;
		}
	}
	int count =0;
	for (index = optind; index < argc; index++)
	{
		count++;
	}
	if(count>0)
	{
		dest = argv[optind];
	}
	if(count == 2)
	{
		d_port = argv[optind+1];
	}
	if(0 == has_key)
	{
		char* str = "1234567812345678";
		if(ser_mode) //server mode on
			server_mode(port,dest,d_port,str);
		else	//client mode on
			client_mode(dest,d_port,str);
	}
	else if(1 == has_key)
	{
		if(ser_mode) //server mode on
			server_mode(port,dest,d_port,keyfile);
		else	//client mode on
			client_mode(dest,d_port,keyfile);
		
	}
	return 0;
}
