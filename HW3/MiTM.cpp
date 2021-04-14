///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in April 12 2021                               //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#include "cipherImplementation.h"
#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <vector>
using namespace std;


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

word reconstructKey(word key1, word key2){
	word key;
	for(int i = 0; i < 16; i++){
		key.nibbles[i] = key1.nibbles[i] | key2.nibbles[i];
	}
	return key;
}



word getRealKey(word forwardKey, word backwardKey, short forwardMask[16], short backwardMask[16]){  // function to merge between the forward key and the backward key
	word key;
	int i = 3;
	short backwardMasktemp[16];
	while(i--){
		backwardKey = keyScheduleDec(backwardKey);
	}
	for(int i = 4; i < 20; i++){
		backwardMasktemp[i & 15] = backwardMask[((i + 4) & 15)];  // &15 is like %16(but faster)
	}
	bool f = true;
	for(i = 0; i < 16; i++){
		if(backwardMasktemp[i] && forwardMask[i]){
			f = f && (forwardKey.nibbles[i] == backwardKey.nibbles[i]);
			key.nibbles[i] = forwardKey.nibbles[i] | backwardKey.nibbles[i];
		}
		else if((!backwardMasktemp[i]) && forwardMask[i]){
			key.nibbles[i] = forwardKey.nibbles[i];	
		}
		else if(backwardMasktemp[i] && (!forwardMask[i])){
			key.nibbles[i] = backwardKey.nibbles[i];	
		}
		else{
			key.nibbles[i] = 0;	
		}
		if(!f){
			break;
		}
	}
	if(i < 16){
		for(i = 0; i < 16; i++){
			key.nibbles[i] = 0;
		}
		cout << "FUCK!" << endl;
	}
	return key;
}



uint64_t MiTM(uint64_t ptctarray[16][2], short forwardMask[16], short backwardMask[16], short matchingNibble){
	uint64_t forwardBFkeyLimit = 1<<20;
	uint64_t backwardBFkeyLimit = 1<<28;
	unordered_set<uint64_t> goodKeys = unordered_set<uint64_t>();
	word plaintext[16];
	word ciphertext[16];

	for(int i = 0; i < 16; i++){  // unpack the input plaintext and ciphertexts
		plaintext[i]  = hextoword(ptctarray[i][0]);
		ciphertext[i] = hextoword(ptctarray[i][1]);
	}
	unordered_multimap<uint64_t, word> h = unordered_multimap<uint64_t, word>();
	for(uint64_t forwardBFkey = 0; forwardBFkey < forwardBFkeyLimit; forwardBFkey++){  // forward stage
		word forwardKey = bfkeyToMaskedKey(forwardBFkey, forwardMask);
		uint64_t matchedNibble = 0;
		for(int i = 0; i < 16; i++){
			matchedNibble |= (((uint64_t)encrypt(plaintext[i], forwardKey, 3).nibbles[matchingNibble])<<(4*i));
		}
		h.insert({matchedNibble,forwardKey});
	}
	for(uint64_t backwardBFkey = 0; backwardBFkey < backwardBFkeyLimit; backwardBFkey++){  // backward stage
		word backwardKey = bfkeyToMaskedKey(backwardBFkey, backwardMask);
		uint64_t matchedNibble = 0;
		for(int i = 0; i < 16; i++){
			matchedNibble |= (((uint64_t)decrypt(ciphertext[i], backwardKey, 5).nibbles[matchingNibble])<<(4*i));
		}
		auto gkey = h.find(matchedNibble);
		if(gkey != h.end()){
			uint64_t key = wordtohex(getRealKey(gkey->second, backwardKey, forwardMask, backwardMask));
			goodKeys.insert(key);
			cout << "masked key: " << hex << setfill('0') << setw(16) << right << key << endl;
			break;
		}
	}

	h.erase(h.begin(), h.end());
	short bfMask[16] = {0};
	uint64_t innerbflimit = 1;
	uint64_t ke = 0;
	short backwardMasktemp[16];
	for(int i = 4; i < 20; i++){
		backwardMasktemp[i & 15] = backwardMask[((i + 4) & 15)];  // &15 is like %16(but faster)
	}
	auto lkey = goodKeys.begin();
	word gdkey = hextoword(*lkey);
	for(int i = 0; i < 16; i++){
		bfMask[i] = !(forwardMask[i]||backwardMasktemp[i]);
		innerbflimit *= ((bfMask[i])? 16:1);
	}
	for(auto& gkey : goodKeys){
		for(uint64_t bfkey = 0; bfkey < innerbflimit; bfkey++){  // BF the masked out bits of the key
			word key = bfkeyToMaskedKey(bfkey,bfMask);
			word templ = hextoword(gkey);
			key = reconstructKey(templ, key);
			bool flag = true;
			for(int i = 0; (i < 16) && flag; i++){  // for each plaintext ciphertext pair do:
				word enc = encrypt(plaintext[i], key, 8);  // get what the key making the plaintext to be
				for(int j = 0; (j < 16) && flag; j++){  // for each nibble in the ciphertext(and the candidate ciphertext) do:
					flag = flag && (enc.nibbles[j] == ciphertext[i].nibbles[j]);  // ask if the nibbles are equal
				}
			}
			if(flag){  // if key was right about all plaintext/ciphertext pairs, it is the key
				ke = wordtohex(key);
				break;
			}
		}
	}
	return ke;
}


int main(){
	uint64_t ptctarray1[16][2] = {{0x75D9E19108BF4EFD, 0x14BB03817A803D0A},
								  {0xF107D2A4DA7E6392, 0x9890E915B26EEDA8},
								  {0x8860E8C6ABA70F04, 0xB00B351894DD273C},
								  {0x21155241F6496480, 0x02D51835A9FB63BE},
								  {0x2F75ACC55CB6C9F7, 0x27F6323CFF646995},
								  {0xC0E0DB589762E08F, 0xBEF2A859602CC1BE},
								  {0xF065037E6A0E3F2F, 0x402C58430E372376},
								  {0x61E14317FB2ED12C, 0x84268CAD7761A8A1},
								  {0x22EB0857ADEDCA62, 0xC038AC535E017103},
								  {0x5A8A5BA69172C3D1, 0x690A6652D1D5E43C},
								  {0x6BD30A2FE5711AE2, 0xAA9AF3C8136FE9FB},
								  {0x3A3BAFE2B76F0B14, 0xA0B1B21FB390AAA3},
								  {0xC65A57B502AFD50C, 0x148FDE7F4BFA6ABD},
								  {0x06991C4D030056B9, 0x20D4E54B5A4E90C7},
								  {0xB2E66A4B68B6BB7B, 0x8EA3F73A0CE6BA96},
								  {0x86A146EE26852A9C, 0xA71D792E04D39811}};

	uint64_t ptctarray2[16][2] = {{0x8829BDBDF735856E, 0xDC8A0AACA10A5806},
								  {0x7C13B9DE58E1C57C, 0xB7D5E8BDFE6816AB},
								  {0x6E3234D9AED2477A, 0xA3E4E072D7C5F68F},
								  {0xC95EDE9783AA189B, 0x44AD6E9B16EFA0FD},
								  {0xB4EBE605D206F988, 0x626813DB71CD83C5},
								  {0x3A3652D5DBF7E6F7, 0x1188748383A0DE6D},
								  {0xC2A3774496B6C173, 0x7A956DECD31067AF},
								  {0x388CC7B6426C7EA3, 0x0ADA632125E705E9},
								  {0x3E14B0D64E6F7622, 0x644D8791C2163F89},
								  {0xD83B8CCAD6C02B98, 0xB281720DFC74DDC6},
								  {0x25F0648D97C8D96D, 0x8C29ABCD706A1184},
								  {0x174B365B5AA6F0E7, 0xEE07CB7903401513},
								  {0x77E1BDFC1DAD034F, 0x079E1B6A370098AB},
								  {0xAA2BC40C5E82E4B5, 0x04F2D5FF67479FA8},
								  {0x5E78BCBA52ECCA4E, 0x45EB39F7AB078180},
								  {0x92DC355F14414A91, 0x1BA3C39D84BF9DB9}};

	short forwardMask[16] =  {1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1};
	short backwardMask[16] = {0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1};
	uint64_t key = MiTM(ptctarray1, forwardMask, backwardMask, 4);
	cout << "key: " << hex << setfill('0') << setw(16) << right << key << endl;


}




