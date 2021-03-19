#include "cipherImplementation.h"
#include <stdio.h>

unsigned int extractNibble(word w, int i){  // extract the nibble starting in bit i(bits i to i+3)
	return (w >> i) & 0xf;
}

word rotateLeft(word w, unsigned int offset){  // rotate the word w <offset> bits to the left(cyclic way)
	offset = offset%WORDSIZE;
	return (w<<offset)|(w>>(WORDSIZE-offset));  // first shift left by offset, than bring the offset to the start
}

word L(word w){  // L, the L from the spec file
	return rotateLeft(w, 15) ^ rotateLeft(w, 32) ^ w; 
}

word applySbox(word w, unsigned short sbox[16]){  // apply the sbox <sbox> on the word w 
	word neword = 0;
	int i;
	for(i = 0; i<64; i+=4){  // for each i 
		unsigned short nibble = extractNibble(w, i);  // get the i'th nibble of w
		neword |= ((word)(sbox[nibble]) << i);  // add the replaced nibble to the start
	}
	return neword;
}



word roundFunction(word w, word key){  // roud function, do one round of TC01
	unsigned short sbox[16] = {0x2, 0x4, 0x5, 0x6, 0x1, 0xA, 0xF, 0x3, 0xB, 0xE, 0x0, 0x7, 0x9, 0x8, 0xC, 0xD};  // the sbox of TC01
	w ^= key;  // first we xor the round key
	w = applySbox(w, sbox);  // than applying the sbox
	w = L(w);  // than calling L
	return w;
}


word encrypt(word plaintext, word key, int rounds){  // encrypt function for TC01
	int r;
	word ciphertext = plaintext;
	for(r=0; r<rounds; r++){  // for each round
		ciphertext = roundFunction(ciphertext, key);  // do round
		key = L(key)^0x3;  // expand key
	}
	return ciphertext;
}


