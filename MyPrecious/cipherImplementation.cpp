#include "cipherImplementation.h"
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <time.h>

//#define DEBUG

uint32_t rotateLeft(uint32_t a, int n){
	return ((a << n) & mask) | ((a >> (32 - n) & mask));
}


uint32_t rotateRight(uint32_t a, int n){
	return ((a >> n) & mask) | ((a << (32 - n) & mask));
}


vector<uint32_t> keySchedule(uint64_t masterKey, int rounds){
	vector<uint32_t> roundKeys = vector<uint32_t>();
	roundKeys.push_back((masterKey & mask));
	roundKeys.push_back(((masterKey >> 32)&mask));
	for(int i = 0; i < rounds-2; i++){
		roundKeys.push_back(roundKeys[roundKeys.size()-1] ^ rotateLeft(roundKeys[roundKeys.size()-2], 7) ^ 0xFF ^ i);
		//cout << hex << uppercase << setfill('0') << setw(16) << roundKeys[roundKeys.size()-1] << endl;
	}
	return roundKeys;
}


uint64_t getKeyFromThreeRoundDecryptionKey(uint64_t decKey, int rounds){
	vector<uint32_t> roundKeys = vector<uint32_t>();
	roundKeys.push_back(((decKey >> 32) & mask));
	roundKeys.push_back((decKey & mask));
	for(int i = 4; i < rounds + 1; i++){
		uint32_t tmp = roundKeys[roundKeys.size()-1] ^ roundKeys[roundKeys.size()-2] ^ 0xFF ^ (MAX(rounds - i, 0));
		roundKeys.push_back(rotateRight(tmp, 7));
		
	}
	return ((uint64_t)roundKeys[roundKeys.size()-1] | (((uint64_t)roundKeys[roundKeys.size()-2]) << 32));
}


uint32_t F(uint32_t w){
	uint32_t w2 = w | rotateLeft(w, 3);
	return (rotateLeft(w, 8) + w2) & mask;
}



uint64_t encrypt(uint64_t w, uint64_t masterKey, int rounds = 23){
	vector<uint32_t> roundKeys = keySchedule(masterKey,rounds);
	uint32_t left = w & mask;
	uint32_t r = (w >> 32) & mask;
	for(int i = 0; i < rounds; i++){
		#ifdef DEBUG
			cout << hex << uppercase << setfill('0') << setw(8) << right << roundKeys[i] << endl;
		#endif
		uint32_t swp = left;
		left ^= roundKeys[i];
		left = F(left);
		left = r ^ left;
		r = swp;
	}
	return (((uint64_t)r) << 32) | left;
}


uint64_t decrypt(uint64_t w, uint64_t masterKey, int rounds = 23){
	vector<uint32_t> roundKeys = keySchedule(masterKey,rounds);
	uint32_t left = w & mask;
	uint32_t r = (w >> 32) & mask;
	for(int i = 0; i < rounds; i++){
		#ifdef DEBUG
		cout << hex << uppercase << setfill('0') << setw(8) << right << roundKeys[rounds-i] << endl;
		#endif
		uint32_t swp = left;
		left ^= roundKeys[rounds-i];
		left = F(left);
		left = r ^ left;
		r = swp;
	}
	return (((uint64_t)r) << 32) | left;
}

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}


void printRelations(){
	
	uint64_t w = 1;
	uint64_t mask = 0xFFFFFFFFFFFFFFFC;
	uint64_t masktag = 0xFFFFFFFFFFFFFFFC;
	for(int i=0;i<32;i++){
		uint64_t flag = 0xFFFFFFFFFFFFFFFF;
		mask = masktag;
		uint64_t outtag = decrypt(0x0123456789ABCDEF, mask, 3) ^ decrypt(0x0123456789ABCDEF ^ 0xF000000000100000, mask, 3);
		//cout <<"hi"<<endl;
		for(int j = 0; j < 4; j++){
			uint64_t key = mask | (((uint64_t)j) << (i * 2));
			uint64_t out = decrypt(0x0123456789ABCDEF ^ 0xF000000000100000, key, 3) ^ decrypt(0x0123456789ABCDEF, key, 3);
			flag = flag & ((out ^ outtag) ^ 0xFFFFFFFFFFFFFFFF);
			//cout << hex << uppercase << setfill('0') << setw(8) << right << (out^outtag) << endl;
		}
//		cout << hex << uppercase << setfill('0') << setw(16) << right << flag << endl;
		if((flag & 0xF000000000100000) == 0xF000000000100000){
			cout << dec << i << "th nibble is unrelated" << endl;
		}
		//cout << endl;
		//cout << hex << setfill('0') << setw(16) << right << mask << endl;
		masktag = (masktag << 2) | 0x0000000000000000;
	}
	cout << endl;

}



void experiment(int a){
	uint64_t key = rand() % 0xFFFFFFFFFFFFFFFF;
	int cnt = 0;
	for(int i = 0; i < (1<<18); i++){
		uint64_t w1 = rand() % 0xFFFFFFFFFFFFFFFF;
		uint64_t w2 = w1 ^ 0x00000000000000010;
		uint64_t c1 = encrypt(w1, key, a);
		uint64_t c2 = encrypt(w2, key, a);

		cout << hex << uppercase << setfill('0') << setw(16) << right << ((c1 ^ c2) & 0xF000000000100000) << endl;	
	}
}
