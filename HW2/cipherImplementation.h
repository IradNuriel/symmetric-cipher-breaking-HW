///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in March 13 2021                               //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_
#include <stdint.h>

struct word { // struct representing a word(key or plaintext or ciphertext)
	unsigned short nibbles[16];
};

typedef struct word word;

word hextoword(uint64_t w);

uint64_t wordtohex(word w);

word keySchdule(word prevKey);

word addRoundKey(word w, word key);

word shiftRowsMixColumns(word w);

word applySbox(word w);

word roundFunction(word w, word key);

word encrypt(word w, word key, int rounds);

void printRelations();

void checkRelations();

#endif