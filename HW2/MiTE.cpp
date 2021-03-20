///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in March 17 2021                               //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#include "cipherImplementation.h"
#include <stdint.h>
#include <iostream>
#include <thread>
#include <vector>
using namespace std;

bool f = false;

word bfkeyToMaskedKey(uint64_t key, short nibbleMask[16]){  // function to generate a key which is aligned with the mask from a commpressed key
	word maskedKey;
	for(int i = 0; i < 16; i+=4){
		// for each nibble, if it is in the mask, put it in the key(with loop unrolling)
		maskedKey.nibbles[i + 0] = (key)     &  (0xF * nibbleMask[i + 0]);
		key = ((unsigned long long int)(key) >> (  4 * nibbleMask[i + 0]));
		maskedKey.nibbles[i + 1] = (key)     &  (0xF * nibbleMask[i + 1]);
		key = ((unsigned long long int)(key) >> (  4 * nibbleMask[i + 1]));
		maskedKey.nibbles[i + 2] = (key)     &  (0xF * nibbleMask[i + 2]);
		key = ((unsigned long long int)(key) >> (  4 * nibbleMask[i + 2]));
		maskedKey.nibbles[i + 3] = (key)     &  (0xF * nibbleMask[i + 3]);
		key = ((unsigned long long int)(key) >> (  4 * nibbleMask[i + 3]));
	}
	return maskedKey;
}



void meetInTheEnd(uint64_t ptctarray[16][2], short keyMask[16], short matchingNibble, uint64_t startingPoint){  // the attack implementation
	word plaintext[16];
	word ciphertext[16];
	uint64_t bfkey=0;
	uint64_t bflimit=0xFFFFFFFFFF;
	uint64_t innerbflimit = 0xFFFFFF;
	for(int i = 0; i < 16; i++){  // unpack the input plaintext and ciphertexts
		plaintext[i]  = hextoword(ptctarray[i][0]);
		ciphertext[i] = hextoword(ptctarray[i][1]);
	}
	for(bfkey = startingPoint; bfkey < bflimit; bfkey++){  // for each key in the masked key world(compressed)
		bool flag = true;
		word key = bfkeyToMaskedKey(bfkey,keyMask);  // get the key in its true form
		for(int i = 0; (i < 16) && flag; i+=4){  //if the key makes the plaintexts agree with their ciphertext on the matching nibble, it is the key mask(with loop unrolling)
			flag = flag && (ciphertext[i + 0].nibbles[matchingNibble] == encrypt(plaintext[i + 0], key, 4).nibbles[matchingNibble]);
			flag = flag && (ciphertext[i + 1].nibbles[matchingNibble] == encrypt(plaintext[i + 1], key, 4).nibbles[matchingNibble]);
			flag = flag && (ciphertext[i + 2].nibbles[matchingNibble] == encrypt(plaintext[i + 2], key, 4).nibbles[matchingNibble]);
			flag = flag && (ciphertext[i + 3].nibbles[matchingNibble] == encrypt(plaintext[i + 3], key, 4).nibbles[matchingNibble]);
		}
		if(flag){  // if key found, I'm winner
			bfkey = wordtohex(key);
			break;
		}
		if(f){  // if other thread found the key, kill me
			return;
		}
	}
	f = true;  // killing all unseccessful threads
	for(int i = 0; i < 16; i++){
		keyMask[i] = !keyMask[i];
	}
	for(uint64_t bfke = 0; bfke < innerbflimit; bfke++){  // BF the masked out bits of the key
		word ke = bfkeyToMaskedKey(bfke,keyMask);
		word key = hextoword(bfkey);
		for(int i = 0; i < 16; i++){  // get the current key
			key.nibbles[i] |= ke.nibbles[i];
		}
		bool flag = true;
		for(int i = 0; (i < 16) && flag; i++){  // for each plaintext ciphertext pair do:
			word enc = encrypt(plaintext[i], key, 4);  // get what the key making the plaintext to be
			for(int j = 0; (j < 16) && flag; j++){  // for each nibble in the ciphertext(and the candidate ciphertext) do:
				flag = flag && (enc.nibbles[j] == ciphertext[i].nibbles[j]);  // ask if the nibbles are equal
			}
		}
		if(flag){  // if key was right about all plaintext/ciphertext pairs, it is the key
			bfkey = wordtohex(key);
			break;
		}
	}
	// print key
	cout << "key: " <<  hex << bfkey << endl;
	return;
	
}



int main(){
	clock_t t;
	vector<thread> vec = vector<thread>();
	short keyMask[16] = {1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1};  // key mask
	uint64_t ptctarray[16][2] = {{0x9C9F86B19B4F6F0E, 0xBB9FCCB7ADC91656},
 								 {0xCA16D5E2D23F323E, 0xAB9FDCDEDCD2774D},
 								 {0x70EF5AA696BBC479, 0x3B487E944EA575ED},
 								 {0x33259EEAF640F955, 0xCB94902E8C5B47CF},
 								 {0xAD6A743B0F0D1D32, 0x08DFC6B26A8A6255},
 								 {0x733C44F34C838C52, 0x1BCD25C933E7282A},
 								 {0x1FE8121880050F79, 0xF6865A73EFD9195F},
 								 {0x7E09715983E023E9, 0xBBC48EB30586BE42},
 								 {0x78D8E4A58EEE585B, 0xCCB92120CE1502AC},
 								 {0x00978A90D2015244, 0x6A301B76C844A274},
 								 {0xE6F67AB8ED8A25C2, 0x087BC65D56675E1C},
 								 {0x0AF12E351A69C523, 0xF2D78A5A7E448C93},
 								 {0x8D49E1C30DAFF973, 0x79B4AF8F42A63B12},
 								 {0x1B3F791BA3A7F49E, 0x95FFA69B8A441FBB},
 								 {0x216F6440B5F0C8AA, 0x45B1770E856DC0DC},
 								 {0x5E95B93F9F1658FD, 0x407E7F07195F5921}};  // array in the format of: {{plaintext0, ciphertext0}, {plaintext1, ciphertext1}, ... , {plaintext16, ciphertext16}}
 	t = clock();
 	for(int i = 0; i < 16; i+=1){  // paralleling the attack, so it will take 2^36 instead of 2^40 
 		vec.push_back(thread(meetInTheEnd, ptctarray, keyMask, 10,i * 0x1000000000));
 	}
 	for(auto& t : vec){
 		t.join();
 	}
 	t = clock() - t;
 	cout << "attack took: " << dec << ((double)t)/CLOCKS_PER_SEC << "seconds" << endl;
}