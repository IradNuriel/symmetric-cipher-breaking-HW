///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                                                                               //
//                  written by Irad Nuriel irad9731@gmail.com                    //
//                        written in Jun 4 2021                                  //
//                                                                               //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_
#include <stdint.h>

typedef uint64_t word;

typedef struct column{
	uint16_t col[4];
} column;

typedef uint16_t row;

word rotateLeft(word w, int n);

word keySchdule(word prevKey);  // the key scheduler

uint16_t galoisMultiplication(uint16_t a, uint16_t b);

column mixColumn(column c);  // function executing shift rows and mix columns at the same time

word bitPermutationMixColumns(word w);

row sigma1(row r0);

row sigma2(row r1);

row sigma3(row r2);

row sigma4(row r3);

word applySbox(word w);  // function for applying the sbox(8 bit)

word roundFunction(word w, word roundKey);  // the round function

word encrypt(word w, word masterKey, int rounds);  // the encryption function

void profileTime();


#endif