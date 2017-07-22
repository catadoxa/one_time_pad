#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

//password sent in handshake header for security
#define PASSWORD "dec"
//max size of text/key
#define MAX_SIZE 100000

int make_client(char *hostname, char *port, struct addrinfo *hints);

int connect_client(struct addrinfo *server);

int send_message(int connectionFD, const void *msg, int len);

int receive_message(int connectionFD, void *buffer, int len, int wait);

void error(char *err_msg, int exit_val);

int read_text(char *buffer, char *filename, int len);

int handshake(int connectionFD, int text_len, int key_len);

int main(int argc, char *argv[]) {
	
	//unnamed parameters: argv[1] = ciphertext, argv[2] = key, argv[3] = port
	
	int connectionFD;
	struct addrinfo hints;
	char text[MAX_SIZE];
	char key[MAX_SIZE];
	int text_len, key_len;
	
	//check that enough args were provided
	if (argc < 4)
		error("CLIENT: Not enough parameters. Usage: 'otp_enc [plaintext] [key] [port number]'", 1);
		
	//read in text
	if((text_len = read_text(text, argv[1], MAX_SIZE)) < 0)
		error("CLIENT: Failed to read ciphertext", 1);
	
	//read in key
	if((key_len = read_text(key, argv[2], MAX_SIZE)) < 0)
		error("CLIENT: Failed to read key", 1);
		
	//check key length
	if(strlen(key) < strlen(text))
		error("CLIENT: Key is not long enough", 1);
	
	//connect to server
	connectionFD = make_client("localhost", argv[3], &hints);
	
	//send password, text length and key length
	if(handshake(connectionFD, text_len, key_len) != 0)
		error("CLIENT: Failed security handshake", 1);
	
	//send ciphertext
	if(!(send_message(connectionFD, text, text_len) > 0))
		error("CLIENT: Failed to send encoded message", 1);
	
	//send key
	if(!(send_message(connectionFD, key, key_len) > 0))
		error("CLIENT: Failed to send key", 1);
	
	//get a return message
	if(!(receive_message(connectionFD, text, text_len, MSG_WAITALL)))
		error("CLIENT: Failed to receive decoded message", 1);
	
	//output text received from server
	if(fprintf(stdout, "%s\n", text) < 0)
		error("CLIENT: Failed to write decoded message to file", 1);
	
	close(connectionFD);
	
	return 0;
}

//conect client to server
int connect_client(struct addrinfo *server) {
	
	struct addrinfo *temp;
	int connectionFD;
	
	//connect to the first address in server structure that succeeds
	for(temp = server; temp != NULL; temp = temp->ai_next) {
		
		//attempt to open socket. on fail continue to next struct
		if((connectionFD = socket(temp->ai_family, temp->ai_socktype, temp->ai_protocol)) == -1)
			continue;
		
		//attempt to connect. on fail close socket and continue to next struct
		if(connect(connectionFD, temp->ai_addr, temp->ai_addrlen) == -1) {
			close(connectionFD);
			continue;
		}
		//if this is reached, connection is established so break loop
		break;
	}
	
	//temp == NULL indicates the end of the list was reached, so no connection
	if(temp == NULL)
		error("CLIENT: Failed to connect to server", 1);
	
	return connectionFD;
}

//setup initial client info and get server info
int make_client(char *hostname, char *port, struct addrinfo *hints) {
	
	struct addrinfo *server;
	int connectionFD;
		
	//set hints members
	memset(hints, 0, sizeof(*hints));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	
	//get server info
	if(getaddrinfo(hostname, port, hints, &server) != 0) {
		fprintf(stderr,"CLIENT: Could not find server on port %s\n", port); 
		exit(2);
	}
	
	connectionFD = connect_client(server);
		
	return connectionFD;
}

//write to socket 
int send_message(int connectionFD, const void *msg, int len) {
	
	int n;
	int to_send = len;
	int chars_writ = 0;
	
	//loop until all charcters have been sent
	while(chars_writ < len) {
		
		n = send(connectionFD, msg + chars_writ, to_send, 0);
		
		if(n < 0)
			error("SERVER: Error writing to socket", 1);
		
		chars_writ += n;
		to_send -= n;
		
	}
			
	return chars_writ;
}


//read message from connectionFD into buffer. Option to wait until len bytes have been received
int receive_message(int connectionFD, void *buffer, int len, int wait) {
	
	int chars_read;
	
	//clear buffer
	memset(buffer, '\0', len);
	
	//read from the socket
	if((chars_read = recv(connectionFD, buffer, len, wait)) < 0)
		error("CLIENT: Error reading from socket.", 1);
		
	return chars_read;
}

//read from file filename into buffer of length len
int read_text(char *buffer, char *filename, int len) {
	
	int FD = open(filename, O_RDONLY);
	
	int retval = read(FD, buffer, len);
	
	close(FD);
	
	//replace trailing newline with null
	retval--;
	buffer[retval] = '\0';
	
	return retval;
}

//print error message and exit
void error(char *err_msg, int exit_val) {
	
	if(errno != 0)
		perror(err_msg);
	else
		fprintf(stderr, "%s\n", err_msg);
	
	exit(exit_val);
}

//send header with password and length of text, length of key. recv password back and compare
int handshake(int connectionFD, int text_len, int key_len) {
	
	//len must be long enough for PASSWORD, two spaces, two ints, and a null
	int len = strlen(PASSWORD) + 23;
	char buff[len];
	
	sprintf(buff, "%s %d %d", PASSWORD, text_len, key_len); 
	
	send_message(connectionFD, buff, len);
	
	memset(buff, '\0', len);
	
	receive_message(connectionFD, buff, len, 0);
	
	//check returned password equals stored password
	return strcmp(buff, PASSWORD);
}
