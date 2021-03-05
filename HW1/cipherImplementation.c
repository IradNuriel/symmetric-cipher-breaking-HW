#include "cipherImplementation.h"


unsigned int extractNibble(word w, int i){
	return (w >> i) & 0xf;
}

word rotateLeft(word w, unsigned int offset){
	offset = offset%WORDSIZE;
	return (w<<offset)|(w>>(WORDSIZE-offset));
}

word L(word w){
	return rotateLeft(w, 15) ^ rotateLeft(w, 32) ^ w;
}

word applySbox(word w, unsigned short sbox[16]){
	word neword = 0;
	int i;
	for(i = 0; i<16; i+=1){
		int j = i*4;
		unsigned int nibble = extractNibble(w, j);
		neword |= ((word)(sbox[nibble]) << j);
	}
	return neword;
}


word roundFunction(word w, word key){
	unsigned short sbox[16] = {0x2, 0x4, 0x5, 0x6, 0x1, 0xA, 0xF, 0x3, 0xB, 0xE, 0x0, 0x7, 0x9, 0x8, 0xC, 0xD};
	w ^= key;
	w = applySbox(w, sbox);
	w = L(w);
	return w;
}


word encrypt(word plaintext, word key, int rounds){
	int r;
	word ciphertext = plaintext;
	for(r=0; r<rounds; r++){
		ciphertext = roundFunction(ciphertext, key);
		key = L(key)^0x3;
	}
	return ciphertext;
}


