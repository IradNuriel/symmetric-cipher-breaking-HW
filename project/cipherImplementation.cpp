///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in Jun 4 2021                                  //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#include "cipherImplementation.h"
#include "constants.h"
#include <stdint.h>
#include <iostream>
#include <iomanip>
#include <time.h>
using namespace std;


word rotateLeft(word w, int n){
    word mask = 0xFFFFFFFFFFFFFFFF;
    return ((w << n) & mask) | ((w >> (64 - n) & mask));
}



word keySchdule(word roundKey){
	return (rotateLeft(roundKey, 15) ^ rotateLeft(roundKey, 32) ^ roundKey ^ 0x3);
}


uint16_t galoisMultiplication(uint16_t a, uint16_t b){// used it to find the lookup tables found in constants.h
	int p = 0;
    int hibitSet = 0;
    int i = 8;
    while(i--){
        if(b & 1){ 
        	p = p ^ a;
        }
        hibitSet = a & 0x80;
        a = a << 1;
        if(hibitSet == 0x80){
        	a = a ^ 0x1B;
        }
        b = b >> 1;
   	}
   	return p % 256;
}

column mixColumn(column c){
	column newColumn;
	newColumn.col[0] = galoisMul2[c.col[0]] ^ c.col[3] ^ c.col[2] ^ galoisMul3[c.col[1]];
	newColumn.col[1] = galoisMul2[c.col[1]] ^ c.col[0] ^ c.col[3] ^ galoisMul3[c.col[2]];
	newColumn.col[2] = galoisMul2[c.col[2]] ^ c.col[1] ^ c.col[0] ^ galoisMul3[c.col[3]];
	newColumn.col[3] = galoisMul2[c.col[3]] ^ c.col[2] ^ c.col[1] ^ galoisMul3[c.col[0]];
	return newColumn;
}




row sigma1(row r0){
	row newR0 = 0;
	newR0 |= (r0 & 0x8000) >>  0;  // 0
	newR0 |= (r0 & 0x4000) >>  6;  // 1
	newR0 |= (r0 & 0x2000) >>  8;  // 2
	newR0 |= (r0 & 0x1000) >> 10;  // 3
	newR0 |= (r0 & 0x0800) <<  3;  // 4
	newR0 |= (r0 & 0x0400) <<  1;  // 5
	newR0 |= (r0 & 0x0200) >>  5;  // 6
	newR0 |= (r0 & 0x0100) >>  7;  // 7
	newR0 |= (r0 & 0x0080) <<  6;  // 8
	newR0 |= (r0 & 0x0040) <<  4;  // 9
	newR0 |= (r0 & 0x0020) <<  2;  // A
	newR0 |= (r0 & 0x0010) >>  4;  // b
	newR0 |= (r0 & 0x0008) <<  9;  // C
	newR0 |= (r0 & 0x0004) <<  7;  // D
	newR0 |= (r0 & 0x0002) <<  5;  // E
	newR0 |= (r0 & 0x0001) <<  3;  // F

	return newR0;
}





row sigma2(row r1){
	row newR1 = 0;
	newR1 |= (r1 & 0x8000) >> 12;  // 0
	newR1 |= (r1 & 0x4000) >>  2;  // 1
	newR1 |= (r1 & 0x2000) >>  4;  // 2
	newR1 |= (r1 & 0x1000) >>  6;  // 3
	newR1 |= (r1 & 0x0800) >>  9;  // 4
	newR1 |= (r1 & 0x0400) <<  5;  // 5
	newR1 |= (r1 & 0x0200) >>  1;  // 6
	newR1 |= (r1 & 0x0100) >>  3;  // 7
	newR1 |= (r1 & 0x0080) >>  6;  // 8
	newR1 |= (r1 & 0x0040) <<  8;  // 9
	newR1 |= (r1 & 0x0020) <<  6;  // A
	newR1 |= (r1 & 0x0010) >>  0;  // B
	newR1 |= (r1 & 0x0008) >>  3;  // C
	newR1 |= (r1 & 0x0004) << 11;  // D
	newR1 |= (r1 & 0x0002) <<  9;  // E
	newR1 |= (r1 & 0x0001) <<  7;  // F

	return newR1;
}


row sigma3(row r2){
	row newR2 = 0;
	newR2 |= (r2 & 0x8000) >>  8;  // 0
	newR2 |= (r2 & 0x4000) >> 14;  // 1
	newR2 |= (r2 & 0x2000) >>  0;  // 2
	newR2 |= (r2 & 0x1000) >>  2;  // 3
	newR2 |= (r2 & 0x0800) >>  5;  // 4
	newR2 |= (r2 & 0x0400) >>  7;  // 5
	newR2 |= (r2 & 0x0200) <<  3;  // 6
	newR2 |= (r2 & 0x0100) <<  1;  // 7
	newR2 |= (r2 & 0x0080) >>  2;  // 8
	newR2 |= (r2 & 0x0040) >>  4;  // 9
	newR2 |= (r2 & 0x0020) << 10;  // A
	newR2 |= (r2 & 0x0010) <<  4;  // B
	newR2 |= (r2 & 0x0008) <<  1;  // C
	newR2 |= (r2 & 0x0004) >>  1;  // D
	newR2 |= (r2 & 0x0002) << 13;  // E
	newR2 |= (r2 & 0x0001) << 11;  // F

	return newR2;
}




row sigma4(row r3){
	row newR3 = 0;
	newR3 |= (r3 & 0x8000) >>  4;  // 0
	newR3 |= (r3 & 0x4000) >> 10;  // 1
	newR3 |= (r3 & 0x2000) >> 12;  // 2
	newR3 |= (r3 & 0x1000) <<  2;  // 3
	newR3 |= (r3 & 0x0800) >>  1;  // 4
	newR3 |= (r3 & 0x0400) >>  3;  // 5
	newR3 |= (r3 & 0x0200) >>  9;  // 6
	newR3 |= (r3 & 0x0100) <<  5;  // 7
	newR3 |= (r3 & 0x0080) <<  2;  // 8
	newR3 |= (r3 & 0x0040) >>  0;  // 9
	newR3 |= (r3 & 0x0020) >>  2;  // A
	newR3 |= (r3 & 0x0010) <<  8;  // B
	newR3 |= (r3 & 0x0008) <<  5;  // C
	newR3 |= (r3 & 0x0004) <<  3;  // D
	newR3 |= (r3 & 0x0002) <<  1;  // E
	newR3 |= (r3 & 0x0001) << 15;  // F

	return newR3;
}






word bitPermutationMixColumns(word w){
	row row0 = sigma1((w >> 48) & 0xFFFF);
	row row1 = sigma2((w >> 32) & 0xFFFF);
	row row2 = sigma3((w >> 16) & 0xFFFF);
	row row3 = sigma4((w >> 0 ) & 0xFFFF);


	//combined bit permutation with mixColumns so that I won't need to reconstruct the state and immidiatly break it up into rows again. 
	column col0, col1;

	col0.col[0] = ((row0&0xFF00)>>8);
	col0.col[1] = ((row1&0xFF00)>>8);
	col0.col[2] = ((row2&0xFF00)>>8);
	col0.col[3] = ((row3&0xFF00)>>8);
	



	col1.col[0] = (row0&0x00FF);
	col1.col[1] = (row1&0x00FF);
	col1.col[2] = (row2&0x00FF);
	col1.col[3] = (row3&0x00FF);
	


	col0 = mixColumn(col0);
	col1 = mixColumn(col1);


	word newWord = 0;

	newWord |= ((word)((col0.col[0] << 8) | col1.col[0]) << 48);
	newWord |= ((word)((col0.col[1] << 8) | col1.col[1]) << 32);
	newWord |= ((word)((col0.col[2] << 8) | col1.col[2]) << 16);
	newWord |= ((word)((col0.col[3] << 8) | col1.col[3]) <<  0);
	return newWord;

}


word applySbox(word w){
	word newW = 0;
	for(int j = 0; j < 64; j += 8){
		int byte = (w >> j) & 0xFF;
		newW |= ((word)sbox[byte]) << j;
	} 
	return newW;
}

word roundFunction(word w, word roundKey){
	
	w = w ^ roundKey;
	w = applySbox(w);
	w = bitPermutationMixColumns(w);
	
	return w;
}

word encrypt(word w, word masterKey, int rounds=7){
	word roundKey = masterKey;
	while(rounds--){
		w = roundFunction(w, roundKey);
		roundKey = keySchdule(roundKey);
	}
	return w;
}

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}



int main(){
	profileTime();
	return 0;
	word state = 0x0123456789ABCDEF;
	word firstRoundkey = 0x00000000FEDCBA98;
	cout << hex << uppercase << setfill('0') << setw(16) << state << endl;

	state = state ^ firstRoundkey;
	cout << hex << uppercase << setfill('0') << setw(16) << state << endl;

	state = applySbox(state);
	cout << hex << uppercase << setfill('0') << setw(16) << state << endl;

	state = bitPermutationMixColumns(state);
	cout << hex << uppercase << setfill('0') << setw(16) << state << endl;

	cout << hex << uppercase << setfill('0') << setw(16) << 0 << " " << hex << uppercase << setfill('0') << setw(16) << 0  << " " << hex << uppercase << setfill('0') << setw(16) << encrypt(0, 0) << endl;
	cout << hex << uppercase << setfill('0') << setw(16) << 0x42 << " " << hex << uppercase << setfill('0') << setw(16) << 0x1 << " " << hex << uppercase << setfill('0') << setw(16) << encrypt(0x42, 0x1) << endl;
	cout << hex << uppercase << setfill('0') << setw(16) << 0x0123456789ABCDEF << " " << hex << uppercase << setfill('0') << setw(16) << 0x00000000FEDCBA98 << " " << hex << uppercase << setfill('0') << setw(16) <<  encrypt(0x0123456789ABCDEF, 0x00000000FEDCBA98) << endl;
	return 0;
}




void profileTime(){
	word key = 0;
	uint64_t startClock = rdtsc();
	clock_t startTime = clock();
	clock_t startTime1 = clock();
	
	while(encrypt(0x0123456789ABCDEF, key) != 0xF0FE14D1C8C16C75){
		key++;
		if((key&0xFFFFFF)==0){
			uint64_t currentClock = rdtsc();
			clock_t currentTime = clock();
			double timer = ((double)(currentTime - startTime1))/CLOCKS_PER_SEC;
			double efficiancy1 = ((double)(currentClock-startClock))/0x1000000;
			double efficiancy2 = 0x1000000/timer;
			cout << "Key            : " << hex << uppercase << setfill('0') << setw(16) << key << endl;
			cout << "Efficiancy(e/s): " << efficiancy2 << " encryption/seconds" << endl;
			cout << "Efficiancy(c/e): " << efficiancy1 << " cycles/encryption" << endl;
			startClock = rdtsc();
			startTime1 = clock();
		}
	}
	cout << "Key found  : " << hex << uppercase << setfill('0') << setw(16) << key << endl;
	cout << "attack took: "	<< dec << (clock()-startTime)/CLOCKS_PER_SEC << " seconds" << endl;	
}



