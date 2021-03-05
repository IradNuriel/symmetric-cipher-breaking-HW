#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_

// decleration for all functions and data types for cipherImplementation.c

#define WORDSIZE 64  // size of one word in bits


typedef unsigned long long int word;  // word is a block of TC01 encryption(and the key)

unsigned int extractNibble(word w, int i);

word rotateLeft(word w, unsigned int offset);

word L(word w);

word applySbox(word w, unsigned short sbox[16]);

word roundFunction(word w, word key);

word encrypt(word plaintext, word key, int rounds);

#endif