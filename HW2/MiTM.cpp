#include "cipherImplementation.h"
#include <stdint.h>
#include <iostream>
#include <unordered_set>
#include <string>

using namespace std;

word bfkeyToMaskedKey(uint64_t key, short nibbleMask[16]){
	word maskedKey = hextoword(0);
	int i;
	for(i = 0; (i < 16) && (key != 0); i++){
		if(nibbleMask[i] == 1){
			maskedKey.nibbles[i] = (key) & 0xF;
			key = ((unsigned long long int)(key)>>4);
		}
	}
	return maskedKey;
}



void meetInTheEnd(uint64_t ptctarray[16][2], short keyMask[16], short matchingNibble){
	word plaintext[16];
	word ciphertext[16];
	uint64_t bfkey=0;
	uint64_t bflimit=0xFFFFFFFFFF;
	uint64_t innerbflimit = 0xFFFFFF;
	std::unordered_set<uint64_t> contestents;
	for(int i = 0; i < 16; i++){
		plaintext[i]  = hextoword(ptctarray[i][0]);
		ciphertext[i] = hextoword(ptctarray[i][1]);
	}
	for(bfkey = 0; bfkey < bflimit; bfkey++){
		bool flag = true;
		word key = bfkeyToMaskedKey(bfkey,keyMask);
		for(int i = 0; i < 16; i++){
			flag = flag && (ciphertext[i].nibbles[matchingNibble] == encrypt(plaintext[i],key,4).nibbles[matchingNibble]);
		}

		if(flag){
			uint64_t l = wordtohex(key);
			cout << hex << l << ":" << flag << endl;
			contestents.insert(l);
		}
	}
	cout << contestents.size() << endl;
	for(int i =0; i < 16; i++){
		keyMask[i] = !keyMask[i];
	}
	for(auto& k : contestents){
		word key = hextoword(k);
		bool flag = true;
		for(bfkey = 0; bfkey < innerbflimit; bfkey++){
			word ke = bfkeyToMaskedKey(bfkey, keyMask);
			for(int i = 0; i < 16; i++){
				key.nibbles[i] = key.nibbles[i] & ke.nibbles[i];
			}
			for(int i = 0; i < 16; i++){	
				word enc = encrypt(plaintext[i],key,4);
				for(int j = 0; j < 16; j++){
					flag = flag && (ciphertext[i].nibbles[j] == enc.nibbles[j]);
				}
			}
			if(flag){
				printf("key: %16llX\n",(unsigned long long int)k);
				break;
			}
		}
	}
}


//0xF000 FFF0 0FFF F0FF --> 10
int main(){
	short keyMask[16] = {1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1};
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
								 {0x5E95B93F9F1658FD, 0x407E7F07195F5921}};
	meetInTheEnd(ptctarray, keyMask, 10);
}