#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_
#include <stdint.h>
#include <vector>
using namespace std;


typedef uint16_t word;

typedef struct state {
	word left;
	word right;
} state;

word applySbox(word w);

word sigma(word w);

vector<word> getRoundKeys(uint64_t masterKey, int rounds);

vector<word> getRoundKeysDec(uint64_t masterKey, int rounds);

uint64_t getDecryptionKeyFromMasterKey(uint64_t masterKey, int rounds);

word F(word w);

state roundFunction(state w, word roundKey);

uint32_t encrypt(uint32_t w, uint64_t masterKey, int rounds);

uint32_t decrypt(uint32_t w, uint64_t masterKey, int rounds, bool keyMode);

void printDDT();

void printRelations();

void checkRelations();



#endif