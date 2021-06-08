#include "cipherImplementation.h"
#include <stdint.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <thread>
#include <mutex>





using namespace std;




mutex mut1,mut2;


bool ff=false;


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
			uint64_t keyNibble = (bfKey >> (cnt * 4)) & 0xF;
			cnt++;
			key |= (keyNibble << (i * 4));
		}
	}
	return key;
}


bool distinguisher(vector<quadruple> data, uint64_t candidateKey, uint32_t mask, uint32_t dout){
	int cnt = 0;
	for(quadruple q : data){
		uint32_t x    = decrypt(q.c1, candidateKey, 4, true);
		uint32_t xtag = decrypt(q.c2, candidateKey, 4, true);
		uint32_t flag = x ^ xtag;
		if((flag & mask) == (dout & mask)){
			cnt++;
		}
	}
	
	return (cnt >= 8);
}





void getCandidates(vector<quadruple> data, uint64_t keyMask, uint32_t matchingMask, uint32_t dout, uint64_t startingPoint){
	uint64_t innerBFLimit = 1LL<<36;
	uint64_t bfLimit = 1LL<<24;
	vector<uint64_t> candidateKeys;
	for(uint64_t bfKey = startingPoint; bfKey < (bfLimit + startingPoint); bfKey++){
		uint64_t candidateKey = bfKeyToMaskedKey(keyMask, bfKey);
		/*
		if((bfKey & 0xFFF) == 0){
			mut1.lock();
			cout << hex << uppercase << setfill('0') << setw(8) << right << bfKey << endl;
			mut1.unlock();
		}
		*/
		if(distinguisher(data, candidateKey, matchingMask, dout) && ((bfKey & 0x000F00FF) != 0x000F00C5)){
			mut2.lock();
			cout << hex << uppercase << setfill('0') << setw(16) << right << candidateKey << ":" << dec << candidateKeys.size() << endl;
			mut2.unlock();
			candidateKeys.push_back(candidateKey);
		}
	}
	keyMask = keyMask ^ 0xFFFFFFFFFFFFFFFF;
	for(uint64_t key : candidateKeys){
		for(uint64_t bfKey = 0; bfKey < innerBFLimit; bfKey++){
			uint64_t candidateKey = bfKeyToMaskedKey(keyMask, bfKey);
			candidateKey |= key;
			
			bool flag = true;
			int i = 0;
			for(quadruple q : data){
				uint32_t p1,p2,c1,c2;
				p1 = q.p1;
				p2 = q.p2;
				c1 = q.c1;
				c2 = q.c2;
				flag = flag && (decrypt(c1, candidateKey, 10, true) == p1) && (decrypt(c2, candidateKey, 10, true) == p2);
				if(ff){
					return;
				}
				if((!flag)||((i++)>2)){
					break;
				}
			}
			if(flag){
				ff = true;
				cand = getDecryptionKeyFromMasterKey(candidateKey,10);
				return;
			}
		}
	}
}



//0x013D1000
uint64_t attack(vector<quadruple> data, uint64_t keyMask, uint32_t matchingMask, uint32_t dout){
	uint64_t bfLimit = 1LL<<28;
	uint64_t innerBFLimit = 1LL<<36;
	uint64_t bfKey = 0;
	
	vector<thread> vec = vector<thread>();
	for(int i = 0; i < 16; i+=1){  // paralleling the attack, so it will take 2^36 instead of 2^40 
 		vec.push_back(thread(getCandidates, data, keyMask, matchingMask, dout, i * ((1LL << 24) + 1)));
 	}
 	for(auto& t : vec){
 		t.join();
 	}
 	
 	/*
	//vector<uint64_t> candidateKeys;
	for(bfKey = 0x00000000; bfKey < bfLimit; bfKey++){
		uint64_t candidateKey = bfKeyToMaskedKey(keyMask, bfKey);
		if((bfKey & 0xFFF) == 0){
			//cout << hex << uppercase << setfill('0') << setw(8) << right << bfKey << endl;
		}
		if(distinguisher(data, candidateKey, matchingMask, dout)){
			cout << hex << uppercase << setfill('0') << setw(16) << right << candidateKey << ":" << dec << candidateKeys.size() << endl;
			candidateKeys.push_back(candidateKey);
		}
	}
	
	keyMask = keyMask ^ 0xFFFFFFFFFFFFFFFF;
	for(uint64_t key : candidateKeys){
		for(bfKey = 0; bfKey < innerBFLimit; bfKey++){
			uint64_t candidateKey = bfKeyToMaskedKey(keyMask, bfKey);
			candidateKey |= key;
			if((bfKey & 0xFFF) == 0){
				cout << hex << uppercase << setfill('0') << setw(16) << right << candidateKey << endl;
			} 
			bool flag = true;
			int i = 0;
			for(quadruple q : data){
				uint32_t p1,p2,c1,c2;
				p1 = q.p1;
				p2 = q.p2;
				c1 = q.c1;
				c2 = q.c2;
				flag = flag && (decrypt(c1, candidateKey, 10, true) == p1) && (decrypt(c2, candidateKey, 10, true) == p2);
				if((!flag)||(i>16)){
					break;
				}
			}
			if(flag){
				return candidateKey;
			}
		}
	}
	*/
	return 0;
}

int main(){
	vector<quadruple> data = vector<quadruple>();
	int n;
	cin>>n;
	for(int i = 0; i < n; i++){
		uint32_t p1;
		uint32_t p2;
		uint32_t c1;
		uint32_t c2;
		cin >> hex >> p1 >> hex >> p2 >> hex >> c1 >> hex >> c2;
		quadruple q;
		q.p1 = p1;
		q.p2 = p2;
		q.c1 = c1;
		q.c2 = c2;
		data.push_back(q);
	}
	attack(data, 0x000000F0FF00FFFF, 0x90F00609, 0x0F0FF0F0);
	cout << "key: " << hex << uppercase << setfill('0') << setw(16) << right << cand << endl;
}