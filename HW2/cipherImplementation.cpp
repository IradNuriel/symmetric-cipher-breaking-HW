///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in March 13 2021                               //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#include "cipherImplementation.h"
#include <iostream>
#include <stdint.h>

using namespace std;


word hextoword(uint64_t w){  // change a state representation into a cell representation 
	word newW;
	for(int i = 0; i < 16; i++){
		newW.nibbles[i] = (w>>i*4)&0xF;
	}
	return newW;
}

uint64_t wordtohex(word w){  // change a cell representation into a state representation
	uint64_t newW = 0;
	for(int i = 0; i < 64; i+=4){
		newW |= ((uint64_t)(w.nibbles[i/4])<<(i));
	}
	return newW;	
}



word addRoundKey(word w, word key){  // xoring with the key(with loop unrolling)
	for(int i = 0; i < 4; i++){
		w.nibbles[2 * i + 0] = w.nibbles[2 * i + 0] ^ key.nibbles[2 * i + 0];
		w.nibbles[2 * i + 1] = w.nibbles[2 * i + 1] ^ key.nibbles[2 * i + 1];
	}
	return w;
}



word keySchedule(word prevKey){  // the key schedualing algorithm
	word key;
	prevKey.nibbles[0] ^= 0X3;
	prevKey.nibbles[1] ^= 0xF;
	prevKey.nibbles[2] ^= 0X3;
	prevKey.nibbles[3] ^= 0XF;
	for(int i = 4; i < 20; i++){
		key.nibbles[i & 15] = prevKey.nibbles[((i + 4) & 15)];  // &15 is like %16(but faster)
	}
	return key;
}


word applySbox(word w){  // function for applying the sbox on a word
	unsigned short sbox[16] = {0xA, 0x5, 0x4, 0x2, 0x6, 0x1, 0xF, 0x3, 0xB, 0xE, 0x7, 0x0, 0x8, 0xD, 0xC, 0x9};
	for(int i = 0; i < 8; i++){  // applying sbox with loop unrolling
		w.nibbles[2 * i + 0] = sbox[(w.nibbles[2 * i + 0])];
		w.nibbles[2 * i + 1] = sbox[(w.nibbles[2 * i + 1])];
	}
	return w;
}


word shiftRowsMIxColumns(word w){  // function combining the shift rows and the mix columns parts of the round
	word newW;
	for(int i = 0; i < 4; i++){  // &3 is like %4(but faster)
		newW.nibbles[i + 12] =  w.nibbles[((i + 0) & 3) + 12 ]  ^  w.nibbles[((i + 2) & 3) + 4];
		newW.nibbles[i + 8 ] =  w.nibbles[((i + 3) & 3) + 8  ]  ^  w.nibbles[((i + 2) & 3) + 4];
		newW.nibbles[i + 4 ] =  w.nibbles[((i + 0) & 3) + 12 ]  ^  w.nibbles[((i + 1) & 3) + 0];
		newW.nibbles[i + 0 ] =  w.nibbles[((i + 2) & 3) + 4  ]  ^  w.nibbles[((i + 1) & 3) + 0];
	}
	return newW;
}


word roundFunction(word w, word key){  // the round function
	w = addRoundKey(w, key);
	w = applySbox(w);
	w = shiftRowsMIxColumns(w);
	return w;
}



word encrypt(word w, word key, int rounds){  // the encryption function
	while(rounds--){  // for each round(loop in competitive programming fasion)
		w = roundFunction(w, key);  // apply the round function
		key = keySchedule(key);  // get next round key
	}
	return w;
}







///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//   from here, there are only functions I used for testing and finding masks    //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////


// function for printing the relation between key nibble and ciphertext nibble
void printRelations(){
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



// function for checking the relation between key nibbles and ciphertext nibble
void checkRelations(){
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

