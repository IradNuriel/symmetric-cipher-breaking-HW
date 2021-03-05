#include <stdio.h>
#include "cipherImplementation.h"



int main(){
	word plaintext = 0x5E93AC02E20411CC;
	word ciphertext = 0x01376B3160378E04;
	word key = 1LL<<25;
	word limit = 1LL<<32;
	while((encrypt(plaintext, key, 20)!=ciphertext)&&(key<limit)){
		key++;
		printf("checking: %16llx\n", key);
	}
	if(encrypt(plaintext, key, 20)==ciphertext){
		printf("real key: %16llx\n", key);
	}else{
		printf("nothing found\n");
	}

}