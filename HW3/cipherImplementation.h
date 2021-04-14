///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in April 12 2021                               //
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

word hextoword(uint64_t w);  // function to convert from cell state representation to representation

uint64_t wordtohex(word w);  // function to convert from cell representation to state representation

word keyScheduleEnc(word prevKey);  // the key scheduler

word keyScheduleDec(word prevKey);  // the key scheduler

word addRoundKey(word w, word key);  // the add round key function

word shiftRowsMixColumns(word w);  // function executing shift rows and mix columns at the same time

word applySbox(word w);  // function for applying the sbox(4 bit)

word roundFunctionEnc(word w, word key);  // the encryption round function

word roundFunctionDec(word w, word key);  // the decryption round function

word encrypt(word w, word key, int rounds);  // the encryption function

word decrypt(word w, word key, int rounds);  // the decryption function

word MixColumnsShiftRowsReverse(word w);  // function executing reverse mix columns and revrrse shift rows at the same time

// two functions for checking thinigs.
void printRelations();

void checkRelations();



#endif