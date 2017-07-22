#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//create file containing indicated number of random uppercase letters and spaces, followed by \n
int main(int argc, char *argv[]) {
	
	int chars;
	int i;
	char pad;

	//check args
	if(argc < 2) {
		fprintf(stderr, "USAGE: 'keygen [# of characters in key]'\n");
		exit(1);		
	}
	
	chars = atoi(argv[1]);
	
	srand(time(NULL));
	
	for(i = 0; i < chars; i++) {
		
		pad = rand() % 27;
		//if 26 add offset to make space char
		if(pad == 26)
			pad = ' ';
		//else, add offset for uppercase letter
		else
			pad += 'A';
		
		fputc(pad, stdout);
		
	}
	//add trailing newline
	fputc('\n', stdout);
	
	return 0;
}