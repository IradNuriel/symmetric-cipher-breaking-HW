#include "cipherImplementation.h"
#include <stdint.h>
#include <vector>
#include <iostream>
#include <iomanip>



using namespace std;

uint64_t cand = 0;


typedef struct quadruple{
	uint32_t p1;
	uint32_t p2;
	uint32_t c1;
	uint32_t c2;
}quadruple;


uint64_t bfKeyToMaskedKey(uint64_t keyMask, uint64_t bfKey){
	uint64_t key = 0;
	int cnt = 0;
	for(int i = 0; i < 16; i++){
		uint64_t maskNibble = (keyMask >> (i * 4)) & 0xF;
		if(maskNibble == 0xF){
			uint64_t keyNibble = (bfKey >> (cnt * 2)) & 0xF;
			cnt += 2;
			key |= (keyNibble << (i * 4));
		}
		else if(maskNibble == 0x3){
			uint64_t keyNibble = (bfKey >> (cnt * 2)) & 0x3;
			cnt += 1;
			key |= (keyNibble << (i * 4));
		}
		else if(maskNibble == 0xC){
			uint64_t keyNibble = (bfKey >> (cnt * 2)) & 0x3;
			cnt += 1;
			key |= (keyNibble << ((i * 4) + 2));
		}
	}
	if((key&keyMask)^key){
		cout << "ERROR!!!!" << endl; 
	}
	return key;
}


bool distinguisher(vector<quadruple> data, uint64_t candidateKey, uint64_t mask, uint64_t dout){
	int cnt = 0;
	for(quadruple q : data){
		uint64_t x    = decrypt(q.c1, candidateKey, 3);
		uint64_t xtag = decrypt(q.c2, candidateKey, 3);
		uint64_t flag = x ^ xtag;
		if((flag & mask) == (dout & mask)){
			cnt++;
		}
	}
	
	return (cnt >= 13);
}




uint64_t attack(vector<quadruple> data1, vector<quadruple> data2){
	//first stage:
	uint64_t limit = 1LL<<22;
	uint64_t bfke = 0;
	uint64_t partialKey = 0;
	for(uint64_t bfkey = 0; bfkey < limit; bfkey++){
		uint64_t candidateKey = bfKeyToMaskedKey(0x0003F3C000000FFF, bfkey);
		if((bfkey&0xFFFF)==0){
			cout << hex << uppercase << setfill('0') << setw(16) << right << candidateKey << endl;
		}
		if(distinguisher(data1, candidateKey, 0xF000000000100000, 0x1000000000100000)){
			cout << hex << uppercase << setfill('0') << setw(16) << right << candidateKey << endl;
			bfke = bfkey;
			break;
		}
	}
	partialKey = bfKeyToMaskedKey(0x0003F3C000000FFF, bfke);
	cout << "key? " << hex << uppercase << setfill('0') << setw(16) << right << partialKey << endl;
	//second stage:
	limit = 1LL<<34;
	for(uint64_t bfkey = 0; bfkey < limit; bfkey++){
		uint64_t candidateKey = bfKeyToMaskedKey(0xCFFC0C33FF3FC000, bfkey) | partialKey;

		if(distinguisher(data2, candidateKey, 0x0F00000000010000, 0x0100000000010000)){
			bfke = bfkey;
			break;
		}
	}
	partialKey = bfKeyToMaskedKey(0xCFFC0C33FF3FC000, bfke) | partialKey;
	cout << "key? " << hex << uppercase << setfill('0') << setw(16) << right << partialKey << endl;
	limit = 1LL<<30;
	quadruple q = data1[0];
	for(uint64_t bfkey = 0; bfkey < limit; bfkey++){
		uint64_t candidateKey = getKeyFromThreeRoundDecryptionKey(bfKeyToMaskedKey(0x3000000C00C03000/* | 0x0003F3C000000FFF*/, bfkey) | partialKey, 7);
		if((encrypt(q.p1, candidateKey, 7)==q.c1)&&(encrypt(q.p2, candidateKey, 7)==q.c2)){
			
			return candidateKey;
		}
	}
	return 0;
}






int main(){
	vector<quadruple> data1 = vector<quadruple>();
	cout << "data1: " << endl;
	for(int i = 0; i < 64; i++){
		uint64_t p1;
		uint64_t p2;
		uint64_t c1;
		uint64_t c2;
		cin >> hex >> p1 >> hex >> p2 >> hex >> c1 >> hex >> c2;
		quadruple q;
		q.p1 = p1;
		q.p2 = p2;
		q.c1 = c1;
		q.c2 = c2;
		cout << hex << uppercase << setfill('0') << setw(16) << p1 << " " << hex << uppercase << setfill('0') << setw(16) << p2 << " " << hex << uppercase << setfill('0') << setw(16) << c1 << " " << hex << uppercase << setfill('0') << setw(16) << c2 << endl;
		data1.push_back(q);
	}
	vector<quadruple> data2 = vector<quadruple>();
	cout << "data2: " << endl;
	for(int i = 0; i < 64; i++){
		uint64_t p1;
		uint64_t p2;
		uint64_t c1;
		uint64_t c2;
		cin >> hex >> p1 >> hex >> p2 >> hex >> c1 >> hex >> c2;
		quadruple q;
		q.p1 = p1;
		q.p2 = p2;
		q.c1 = c1;
		q.c2 = c2;
		cout << hex << uppercase << setfill('0') << setw(16) << p1 << " " << hex << uppercase << setfill('0') << setw(16) << p2 << " " << hex << uppercase << setfill('0') << setw(16) << c1 << " " << hex << uppercase << setfill('0') << setw(16) << c2 << endl;
		data2.push_back(q);
	}
	cand = attack(data1, data2);
	cout << "key: " << hex << uppercase << setfill('0') << setw(16) << right << cand << endl;
}