#include "cipherImplementation.h"
#include <time.h>
#include <stdio.h>


//time profiling file, used to check what is slower, the sbox or the L, got to the conclusion of sbox.

void profileRound(int times){
	int i;
	double timeSbox=0,timeL=0;
	word w = 0x0123456789abcdef;
	unsigned short sbox[16] = {0x2, 0x4, 0x5, 0x6, 0x1, 0xA, 0xF, 0x3, 0xB, 0xE, 0x0, 0x7, 0x9, 0x8, 0xC, 0xD};
	clock_t t;

	t = clock();
	for(i=0; i < times; i++){
		L(w);
	}
	t = clock() - t;
	timeL = ((double)t)/CLOCKS_PER_SEC;



	t = clock();
	for(i=0; i < times; i++){
		applySbox(w, sbox);
	}
	t = clock() - t;
   	timeSbox = ((double)t)/CLOCKS_PER_SEC;

	printf("sbox:    %lfs\n", timeSbox);
	printf("L:       %lfs\n", timeL);
}



int main(){
	profileRound(20000);
}