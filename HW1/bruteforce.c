#include <stdio.h>
#include <time.h>
#include "cipherImplementation.h"

//the main bruteforce file

int main(){
	word plaintext = 0x5E93AC02E20411CC;  // the plaintext from the website 
	word ciphertext = 0x01376B3160378E04;  // the ciphertext from the website
	word key = 0;  // key to try
	word limit = 1LL<<32;  // maximum key to try
	clock_t t;
	double time = 0;
	t = clock();
	while((encrypt(plaintext, key, 20)!=ciphertext)&&(key<limit)){  // all time when we don't have the encryption key and we don't have too big of a key:
		key++;  // increase the key
	}
	t = clock() - t;
	time = ((double)t)/CLOCKS_PER_SEC;
	printf("attack took:  %lf seconds\n", time);
	if(encrypt(plaintext, key, 20)==ciphertext){  // if found key is the right key
		printf("real key: %16llx\n", key);  // print the key
	}else{
		printf("nothing found\n");  // if no key was found, tell me
	}

}