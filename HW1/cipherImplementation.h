#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_


#define WORDSIZE 64 


typedef unsigned long long int word;

unsigned int extractNibble(word w, int i);

word rotateLeft(word w, unsigned int offset);

word L(word w);

word applySbox(word w, unsigned short sbox[16]);

word roundFunction(word w, word key);

word encrypt(word plaintext, word key, int rounds);


#endif