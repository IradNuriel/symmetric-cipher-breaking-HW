#include "cipherImplementation.h"
#include <assert.h>
#include <stdint.h>
#include <algorithm>
#include <vector>
#include <iostream>
#include <iomanip>

using namespace std;

word applySbox(word w){
	word newW = 0;
	unsigned short sbox[16] = {0xE, 0xB, 0x4, 0x6, 0xA, 0xD, 0x7, 0x0, 0x3, 0x8, 0xF, 0xC, 0x5, 0x9, 0x1, 0x2};
	for(int i = 0; i < 4; i++){
		unsigned short nibble = (w >> (i*4)) & 0xF;
		newW |= (((word)sbox[nibble]) << i*4);
	}
	return newW;
}


word sigma(word w){
	word newW = 0;
	newW |= (w & 0b1100000000001100) >> 1;
	newW |= (w & 0x2000) >> 6;
	newW |= (w & 0x1000) >> 8;
	newW |= (w & 0x0C00) >> 5;
	newW |= (w & 0x0200) << 6;
	newW |= (w & 0x0100) << 4;
	newW |= (w & 0x00C0) << 3;
	newW |= (w & 0x0020) >> 2;
	newW |= (w & 0x0010) >> 4;
	newW |= (w & 0x0002) << 10;
	newW |= (w & 0x0001) << 8;
	return newW;
}


vector<word> getRoundKeys(uint64_t masterKey, int rounds){
	vector<word> roundKeys = vector<word>();
    for(int i = 0; i < 4; i++){
    	roundKeys.push_back(masterKey&0xFFFF);
    	masterKey = masterKey >> 16;
    }

    reverse(roundKeys.begin(), roundKeys.end());

    for(int i = 4; i < rounds; i++){
        word rk = roundKeys[i-4] ^ roundKeys[i-1] ^ sigma(roundKeys[i-2]) ^ 0xC;
        roundKeys.push_back(rk);
    }
    return roundKeys;
}



vector<word> getRoundKeysDec(uint64_t masterKey, int rounds){
	vector<word> roundKeys = vector<word>();
    for(int i = 0; i < 4; i++){
    	roundKeys.push_back(masterKey&0xFFFF);
    	masterKey = masterKey >> 16;
    }

    for(int i = 4; i < rounds; i++){
        word rk = roundKeys[i-4] ^ roundKeys[i-3] ^ sigma(roundKeys[i-2]) ^ 0xC;
        roundKeys.push_back(rk);
    }
    return roundKeys;
}

uint64_t getDecryptionKeyFromMasterKey(uint64_t masterKey, int rounds = 10){
	assert(rounds>=4);
	uint64_t decKey = 0;
	vector<word> roundKeys = getRoundKeys(masterKey, rounds);
    reverse(roundKeys.begin(), roundKeys.end());
    for(int i = 4; i >= 0; i--){
    	decKey = ((uint64_t)decKey) << 16;
    	decKey |= roundKeys[i];
    	
    }
    return decKey;
}



word F(word w){
	return sigma(applySbox(w));
}

state roundFunction(state w, word roundKey){
	state newState;
	newState.right = w.left;
	newState.left  = F(w.left) ^ w.right ^ roundKey;
	return newState;
}

uint32_t encrypt(uint32_t w, uint64_t masterKey, int rounds = 16){
	state ws;
	ws.left  = (w >> 16) & 0xFFFF;
	ws.right =  w        & 0xFFFF;

	vector<word> roundKeys = getRoundKeys(masterKey, rounds);
	for(int i = 0; i < rounds; i++){
		ws = roundFunction(ws,roundKeys[i]);
	}
	w = 0;
	w |= ((uint32_t) ws.right)      ;
	w |= ((uint32_t) ws.left ) << 16;
	return w;
}



uint32_t decrypt(uint32_t w, uint64_t masterKey, int rounds = 16, bool keyMode = false){
	state ws;
	ws.right = (w >> 16) & 0xFFFF;
	ws.left  =  w        & 0xFFFF;
	
	if(!keyMode){
		masterKey = getDecryptionKeyFromMasterKey(masterKey, rounds);
		
	}
	vector<word> roundKeys = getRoundKeysDec(masterKey, rounds);
    for(int i = 0; i < rounds; i++){
		ws = roundFunction(ws,roundKeys[i]);
	}
	w = 0;
	w |= ((uint32_t) ws.left )      ;
	w |= ((uint32_t) ws.right) << 16;
	return w;
}



void printDDT(){
	unsigned short sbox[16] = {0xE, 0xB, 0x4, 0x6, 0xA, 0xD, 0x7, 0x0, 0x3, 0x8, 0xF, 0xC, 0x5, 0x9, 0x1, 0x2};
	int ddt[16][16];
	for(int i = 0; i<16;i++){
		for(int j = 0; j<16;j++){
			ddt[i][j] = 0;
		}	
	}
	for(int inDiff = 0; inDiff < 16; inDiff++){
		for(int x = 0; x < 16; x++){
			int xtag = x ^ inDiff;
			int outDiff = sbox[x] ^ sbox[xtag];
			ddt[inDiff][outDiff]++;
		}
	}
	cout << "  \\ o ";
	for(int i = 0; i<16;i++){
		cout << hex << setfill(' ') << setw(2) << right << i << (((i+1)<16)? ", " : "");
	}
	cout << endl;
	cout << " i \\" << endl << endl;
	for(int i = 0; i<16;i++){
		cout << hex << setfill(' ') << setw(2) << right << i << ":   ";	
		for(int j = 0; j<16;j++){
			cout << dec << setfill(' ') << setw(2) << right << ddt[i][j] << (((j+1)<16)? ", " : "");
		}
		cout << endl << endl;
	}
}


void printRelations(){
	
	uint32_t w = 1;
	uint64_t mask = 0xFFFFFFFFFFFFFFF0;
	uint64_t masktag = 0xFFFFFFFFFFFFFFF0;
	for(int i=0;i<16;i++){
		uint32_t flag = 0xFFFFFFFF;
		mask = masktag;
		uint32_t outtag = decrypt(0x81234567, mask, 4, true) ^ decrypt(0x81234567 ^ 0x00F00F0F, mask, 4, true);
		//cout <<"hi"<<endl;
		for(int j = 0; j < 16; j++){
			uint64_t key = mask | (((uint64_t)j) << (i * 4));
			uint32_t out = decrypt(0x81234567 ^ 0x00F00F0F, key, 4, true) ^ decrypt(0x81234567, key, 4, true);
			flag = flag & ((out ^ outtag) ^ 0xFFFFFFFF);
			//cout << hex << uppercase << setfill('0') << setw(8) << right << (out^outtag) << endl;
		}
		cout << hex << uppercase << setfill('0') << setw(8) << right << flag << endl;
		if((flag & 0x90F00609) == 0x90F00609){
			cout << dec << i << "th nibble is unrelated" << endl;
		}
		cout << endl;
		//cout << hex << setfill('0') << setw(16) << right << mask << endl;
		masktag = (masktag << 4) | 0x000000000000000F;
	}
	cout << endl;

}



void checkRelations(){
	uint32_t w = 0x01234567;
	uint64_t mask = 0x000000FF0F0F00FF;//0x0FF0FFF00F0FF00F
	uint32_t flag = 0xFFFFFFFF;
	uint32_t out = decrypt(encrypt(w, mask, 10),mask,3);
	for(uint64_t i = 0; i < 16; i++){
		for(uint64_t j = 0; j < 16; j++){
			for(uint64_t k = 0; k < 16; k++){
				for(uint64_t s = 0; s < 16; s++){
					for(uint64_t t = 0; t < 16; t++){
						for(uint64_t r = 0; r < 16; r++){
							for(uint64_t a = 0; a < 16; a++){
								uint64_t key = mask + (i*0x1000000000000000 + j*0x100000000000 + k*0x10000000000 + s*0x10000000 + t*0x100000 + r*0x1000 + a*0x100);
								
								uint32_t outtag = decrypt(encrypt(w, mask, 10),key,3);
								flag = flag & (out ^ outtag ^ 0xFFFFFFFF);

								if(false){
									cout << hex << setfill('0') << setw(16) << right << key << " : ";
									cout << hex << setfill('0') << setw(8) << right << flag << endl;
								}
								if(flag==0){
									goto end;
								}
							}
						}
					}
				}
			}
		}
	}
	end:
	cout << hex << setfill('0') << setw(8) << right << flag << endl;
}


void experiment(int a){
	uint64_t key = rand() % 0xFFFFFFFFFFFFFFFF;
	int cnt = 0;
	for(int i = 0; i < (1<<12); i++){
		uint32_t w1 = rand() % 0xFFFFFFFF;
		uint32_t w2 = w1 ^ 0x00020002;
		uint32_t c1 = encrypt(w1, key, a);
		uint32_t c2 = encrypt(w2, key, a);
		cnt += (((c1^c2)==0x00020002));
		cout << hex << uppercase << setfill('0') << setw(8) << right << (c1^c2) << endl;
			
	}
}





int main(){
	srand (time(NULL));
	int a;
	cin >> a;

	experiment(a);
}


