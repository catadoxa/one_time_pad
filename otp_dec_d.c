#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

//max size of text/key
#define MAX_SIZE 100000
//password sent in handshake header for security
#define PASSWORD "dec"

int send_message(int connectionFD, const void *msg, int len);

int receive_message(int connectionFD, void *buffer, int len, int wait);

int make_server(int port, struct sockaddr_in *server);

void reaper(int signo);

int set_reaper(struct sigaction *handler);

void run_child(int connectionFD);

void error(char *err_msg, int exit_val);

int handshake(int connectionFD, int *text_len, int *key_len);

void decode(char *text, char *key);

char decode_char(char code, char pad);

int main(int argc, char *argv[]) {
	
	//unnamed parameter argv[1] = port number
	
	int listenerFD, connectionFD;
	socklen_t size_of_client;
	int chars_read;
	struct sockaddr_in server, client;
	
	//declare and set handler to reap zombies. Handler defined in set_reaper
	struct sigaction handler;
	if(set_reaper(&handler) == -1)
		error("SERVER: sigaction", 1);
	
	//check that enough args where provided
	if (argc < 2)
		error("SERVER: Not enough parameters Usage: 'otp_enc_d [port number] &'\n", 1);

	//create the server and set listenerFD as the returned file descriptor
	//convert string port arg to int to use as param
	listenerFD = make_server(atoi(argv[1]), &server);
	
	//listen on an infinite loop
	listen(listenerFD, 5);
	while(1) {
	
		//accept a connection
		size_of_client = sizeof(client);
		if((connectionFD = accept(listenerFD, (struct sockaddr *)&client, &size_of_client)) < 0)
			error("SERVER: Error connecting to client\n", 1);
		
		//fork off a child (!fork()) == true indicates that we are in the child process
		if(!fork()) {
			//child isn't listening, so close listener
			close(listenerFD);
			run_child(connectionFD);
		}
		//parent doesn't need connectionFD, so close it
		close(connectionFD);
	}	
	close(listenerFD);

	return 0;
}

//print error message and exit
void error(char *err_msg, int exit_val) {
	
	if(errno != 0)
		perror(err_msg);
	else
		fprintf(stderr, "%s\n", err_msg);
	
	exit(exit_val);
}

//child process communicates with client and performs decoding
void run_child(int connectionFD) {
	
	char text[MAX_SIZE];
	char key[MAX_SIZE];
	int key_len, text_len;
	
	//security handshake checks password, gets key and text lengths
	if(handshake(connectionFD, &text_len, &key_len) != 0)
		fprintf(stderr, "SERVER: Failed security handshake\n");
	
	//get ciphertext
	if(!(receive_message(connectionFD, text, text_len, MSG_WAITALL)))
		error("SERVER: Failed to receive encoded message", 1);
	
	//get key
	if(!(receive_message(connectionFD, key, key_len, MSG_WAITALL)))
		error("SERVER: Failed to receive key", 1);
	
	//decode
	decode(text, key);
	
	//send back decoded message
	if(!(send_message(connectionFD, text, text_len) > 0))
		error("SERVER: Failed to send decoded message", 1);
	
	close(connectionFD);
	
	exit(0);
}

//turns a coded char back to the original
char decode_char(char code, char pad) {
	
	//convert coded chars to numbers from 0 to 26
	if(code == ' ')
		code = 26;
	else
		code -= 'A';
	
	//convert pad chars to numbers
	if(pad == ' ')
		pad = 26;
	else
		pad -= 'A';
	
	//subtract the pad and add 27 to value from 0 to 26
	code = code - pad;
	if(code < 0)
		code += 27;
	
	//convert back to a char
	if(code == 26)
		code = ' ';
	else
		code += 'A';
	
	return code;	
}

//loop through text and decode each character
void decode(char *text, char *key) {
	
	int i;
	for(i = 0; i < strlen(text); i++)
		text[i] = decode_char(text[i], key[i]);
	
	text[i] = '\0';
	
}

//define server information, create and bind to socket
int make_server(int port, struct sockaddr_in *server) {
	
	int FD;
	//clear server
	memset(server, 0, sizeof(*server));
	
	//set server member values and flags
	server->sin_family = AF_INET;
	server->sin_port = htons(port);
	server->sin_addr.s_addr = INADDR_ANY;

	//set up socket
	if((FD = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		error("SERVER: Failed to create server socket.\n", 1);
	
	//bind the socket to the server address
	if (bind(FD, (struct sockaddr *)server, sizeof(*server)) < 0)
		error("SERVER: Failed to bind socke to address.\n", 1);
	
	return FD;
}

//write message to socket
int send_message(int connectionFD, const void *msg, int len) {
	
	int n;
	int to_send = len;
	int chars_writ = 0;
	
	//loop all characters are sent
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
		error("SERVER: Error reading from socket.\n", 1);
		
	return chars_read;
}

//reap zombiez
void reaper(int signo) {
	
	//save the old error number
	int saved_err = errno;
	//reap 'em!
	while(waitpid(-1, NULL, WNOHANG) > 0);
	//reset errno
	errno = saved_err;
	
}

//set up the zombie handler
int set_reaper(struct sigaction *handler) {
	
	//set handler, mask, and flags
	handler->sa_handler = reaper;
	sigemptyset(&(handler->sa_mask));
	handler->sa_flags = SA_RESTART;
	
	return sigaction(SIGCHLD, handler, NULL);
}

//security handshake compares passwords, receives length of text and key
int handshake(int connectionFD, int *text_len, int *key_len) {
	
	int len = strlen(PASSWORD) + 23;
	char buff[len];
	char pass[strlen(PASSWORD) + 1];
	
	receive_message(connectionFD, buff, len, 0);
	
	sscanf(buff, "%s %d %d", pass, text_len, key_len);
	
	send_message(connectionFD, PASSWORD, strlen(PASSWORD));

	return strcmp(pass, PASSWORD);
}
