///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in April 12 2021                               //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#include "cipherImplementation.h"
#include <iostream>
#include <stdint.h>
#include  <iomanip>
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
	for(int i = 4; i < 8; i++){
		w.nibbles[2 * i + 0] = w.nibbles[2 * i + 0] ^ key.nibbles[2 * i + 0];
		w.nibbles[2 * i + 1] = w.nibbles[2 * i + 1] ^ key.nibbles[2 * i + 1];
	}
	return w;
}



word keyScheduleEnc(word prevKey){  // the key schedualing algorithm for encryption
	word key;
	prevKey.nibbles[0] ^= 0X3;
	for(int i = 4; i < 20; i++){
		key.nibbles[i & 15] = prevKey.nibbles[((i + 4) & 15)];  // &15 is like %16(but faster)
	}
	return key;
}



word keyScheduleDec(word prevKey){  // the key schedualing algorithm for decryption
	word key;
	for(int i = 4; i < 20; i++){
		key.nibbles[(i + 4) & 15] = prevKey.nibbles[(i & 15)];  // &15 is like %16(but faster)
	}
	key.nibbles[0] = key.nibbles[0] ^ 0X3;
	return key;
}


word applySbox(word w, unsigned short sbox[16]){  // function for applying the sbox on a word
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
		newW.nibbles[i + 0 ] =  w.nibbles[((i + 2) & 3) + 4  ]                                 ;
	}
	return newW;
}


word roundFunctionEnc(word w, word key){  // the round function for encryption
	unsigned short sbox[16] = {0x2, 0x4, 0x5, 0x6, 0x1, 0xA, 0xF, 0x3, 0xB, 0xE, 0x0, 0x7, 0x9, 0x8, 0xC, 0xD};
	w = addRoundKey(w, key);
	w = applySbox(w, sbox);
	w = shiftRowsMIxColumns(w);
	return w;
}


word encrypt(word w, word key, int rounds){  // the encryption function
	while(rounds--){  // for each round(loop in competitive programming fasion)
		w = roundFunctionEnc(w, key);  // apply the round function
		key = keyScheduleEnc(key);  // get next round key
	}
	return w;
}


word MixColumnsShiftRowsReverse(word w){  // the mixColumnsShiftRows for decryption
	word newW;
	for(int i = 0; i < 4; i++){  // &3 is like %4(but faster)
		newW.nibbles[((i + 0) & 3) + 12] =  w.nibbles[i + 12] ^ w.nibbles[i + 0]                   ;
		newW.nibbles[((i + 3) & 3) + 8 ] =  w.nibbles[i + 8 ] ^ w.nibbles[i + 0]                   ;
		newW.nibbles[((i + 2) & 3) + 4 ] =  w.nibbles[i + 0 ]                                      ;
		newW.nibbles[((i + 1) & 3) + 0 ] =  w.nibbles[i + 12] ^ w.nibbles[i + 4] ^ w.nibbles[i + 0];
	}
	return newW;
}



word roundFunctionDec(word w, word key){  // the round function for decryption
	unsigned short sbox[16] = {0xA, 0x4, 0x0, 0x7, 0x1, 0x2, 0x3, 0xB, 0xD, 0xC, 0x5, 0x8, 0xE, 0xF, 0x9, 0x6};
	w = MixColumnsShiftRowsReverse(w);
	w = applySbox(w, sbox);
	w = addRoundKey(w, key);
	return w;
}


word decrypt(word w, word key, int rounds){  // the decryption function
	int r = rounds;
	while(r--){  // for each round(loop in competitive programming fasion)
		key = keyScheduleEnc(key);
	}
	while(rounds--){  // for each round(loop in competitive programming fasion)
		key = keyScheduleDec(key);  // get next round key
		w = roundFunctionDec(w, key);  // apply the round function
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
	uint64_t mask = 0XFFFFFFFFFFFFFFFF;
	int cnt[16] = {0};
	for(int j = 16;j>0;j--){
		cout << hex << j-1;
		flag[j] = true;
	}
	cout << endl;
	word m = hextoword(mask);
	for(int i=0;i<16;i++){
		a = encrypt(w,m,0);
		for(int j = 0;j<16;j++){
			m.nibbles[i] = j;
			for(int k = 0;k<16;k++){
				word enc = encrypt(w,m,0);
				flag[k    ] = flag[k    ] && ((a.nibbles[k]) == (enc.nibbles[k]));
				//flag[2*k + 1] = flag[2*k + 1] && ((a.nibbles[k] & 0xC) == (enc.nibbles[k] & 0XC));
			}
		}
		m.nibbles[i] = 0;
		a = decrypt(w,m,4);
		for(int j = 0;j<16;j++){
			m.nibbles[i] = j;
			for(int k = 0;k<16;k++){
				word dec = decrypt(w,m,4);
				flag[k    ] = flag[k    ] && ((a.nibbles[k]) == (dec.nibbles[k]));
				//flag[2*k + 1] = flag[2*k + 1] && ((a.nibbles[k] & 0xC) == (dec.nibbles[k] & 0XC));
			}
		}
		/*
		for(int j = 16;j>0;j--){
			cout << hex << flag[j-1];
			cnt[j-1] += (flag[j-1])? 1:0;
			flag[j-1] = true;
		}
		cout << endl;
		*/
	
		cout << i << "th nibble of key is unrelated to bit pairs:";
		for(int j=0;j<16;j++){
			if(flag[j]){
				cout << dec << j << " ";
				cnt[j]++;
			}
			flag[j] = true;
		}
		cout << "of the ciphertext" << endl;
	
		m.nibbles[i] = 0x1;
		m.nibbles[(i+1)%16]=0;
	}
	int max = -1;
	int maxind = -1;
	for(int i = 0; i < 16; i++){
		if(cnt[i]>max){
			max = cnt[i];
			maxind = i;
		}
		cout << cnt[i] << " ";
	}
	cout << endl << maxind << endl;
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

/*
int main(){
	printRelations();
}

*/