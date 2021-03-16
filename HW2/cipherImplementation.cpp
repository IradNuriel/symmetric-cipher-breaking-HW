#include "cipherImplementation.h"
#include <iostream>
#include <stdint.h>
#include <time.h>


using namespace std;


word hextoword(uint64_t w){
	word newW;
	int i;
	for(i = 0; i < 16; i++){
		newW.nibbles[i] = (w>>i*4)&0xF;
	}
	return newW;
}

uint64_t wordtohex(word w){
	uint64_t newW = 0;
	int i;
	for(i = 0; i < 64; i+=4){
		newW |= ((uint64_t)(w.nibbles[i/4])<<(i));
	}
	return newW;	
}



word addRoundKey(word w, word key){
	int i;
	for(i = 0; i < 8; i++){
		w.nibbles[i] = w.nibbles[i] ^ key.nibbles[i];
	}
	return w;
}



word keySchedule(word prevKey){
	word key;
	int i;
	prevKey.nibbles[0] ^= 0X3;
	prevKey.nibbles[1] ^= 0xF;
	prevKey.nibbles[2] ^= 0X3;
	prevKey.nibbles[3] ^= 0XF;
	for(i = 4; i < 20; i++){
		key.nibbles[i % 16] = prevKey.nibbles[((i + 4) % 16)];
	}
	return key;
}


word applySbox(word w){
	int i;
	unsigned short sbox[16] = {0xA, 0x5, 0x4, 0x2, 0x6, 0x1, 0xF, 0x3, 0xB, 0xE, 0x7, 0x0, 0x8, 0xD, 0xC, 0x9};
	for(i = 0; i < 16; i++){
		w.nibbles[i] = sbox[(w.nibbles[i])];
	}
	return w;
}


word shiftRowsMIxColumns(word w){
	word newW;
	int i;
	for(i = 0; i < 4; i++){
		newW.nibbles[i + 12] =  w.nibbles[i + 12]             ^  w.nibbles[((i + 2) % 4) + 4];
		newW.nibbles[i + 8]  =  w.nibbles[((i + 3) % 4) + 8]  ^  w.nibbles[((i + 2) % 4) + 4];
		newW.nibbles[i + 4]  =  w.nibbles[i + 12]             ^  w.nibbles[((i + 1) % 4)];
		newW.nibbles[i]      =  w.nibbles[((i + 2) % 4) + 4]  ^  w.nibbles[((i + 1) % 4)];
	}
	return newW;
}


word roundFunction(word w, word key){
	w = addRoundKey(w, key);
	w = applySbox(w);
	w = shiftRowsMIxColumns(w);
	return w;
}



word encrypt(word w, word key, int rounds){
	int i;
	for(i = 0; i < rounds; i++){
		w = roundFunction(w, key);
		key = keySchedule(key);
	}
	return w;
}


void timeEncryption(){
	word w = hextoword(0x70EF5AA696BBC479);
	word mask = hextoword(0X0FFFF0F0FFFFFF0F);
	word a = encrypt(w, mask, 20);
	wordtohex(a);
}



// main for printing the relation between key nibble and ciphertext nibble
/*
void main1(){
	word w = hextoword(0);
	word a;
	bool flag[16];
	uint64_t mask = 0XFFFFFFFFFFFFFFF0;
	int cnt[16] = {0};
	for(int j = 16;j>0;j--){
		cout << hex << j-1;
		flag[j] = true;
	}
	cout << endl;
	word m = hextoword(mask);
	for(int i=0;i<16;i++){
		a = encrypt(w,m,4);
		for(int j = 0;j<16;j++){
			m.nibbles[i] = j;
			for(int k = 0;k<16;k++){
				flag[k] = flag[k] && (a.nibbles[k] == encrypt(w,m,4).nibbles[k]);
			}
		}
		cout << i << "th nibble of key is unrelated to nibbles:";
		for(int j=0;j<16;j++){
			if(flag[j]){
				cout << dec << j << " ";
				cnt[j]++;
			}
			flag[j] = true;
		}
		cout << "of the ciphertext" << endl;
		m.nibbles[i] = 0xE;
		m.nibbles[(i+1)%16]=0;
	}
	int max = -1;
	int maxind = -1;
	for(int i = 0; i < 16; i++){
		if(max <= cnt[i]){
			maxind = i;
			max = cnt[i];
		}
	}
	cout << maxind <<endl;
}




void main2(){
	word w = hextoword(0);
	int i,j,k,s,t,r,a,d;
	bool flag[16];
	for(i=0;i<16;i++){
		flag[i]=true;
	}
	word mask = hextoword(0X0F000FFFF0FFFF0F);
	word l = encrypt(w,mask,4);
	for(i = 0;i<16;i++){
		mask.nibbles[15] = i;
		for(j = 0;j<16;j++){
			mask.nibbles[14] = j;
			for(k = 0;k<16;k++){
				mask.nibbles[13] = k;
				for(s = 0;s<16;s++){
					mask.nibbles[9] = s;
					for(t = 0;t<16;t++){
						mask.nibbles[4] = t;
						for(a = 0;a<16;a++){
							mask.nibbles[3] = a;
							for(d = 0;d<16;d++){
								flag[d] = flag[d] && (encrypt(w,mask,4).nibbles[d] == l.nibbles[d]);
							}
						}
					}
				}
			}
		}
	}
	end:
	for(i=15;i>=0;i--){
		cout << hex << i;
	}
	cout<<endl;
	for(i=15;i>=0;i--){
		cout << flag[i];
	}
	cout<<endl;
}



int main(){
	main2();
}
*/