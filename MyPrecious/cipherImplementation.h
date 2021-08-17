#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_
#include <stdint.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <time.h>

using namespace std;

const uint32_t mask = 0xFFFFFFFF;

#define MAX(a,b) (((a)>(b))?(a):(b))

uint32_t rotateLeft(uint32_t a, int n);

uint32_t rotateRight(uint32_t a, int n);

vector<uint32_t> keySchedule(uint64_t masterKey, int rounds);

uint64_t getKeyFromThreeRoundDecryptionKey(uint64_t decKey, int rounds);

uint32_t F(uint32_t w);

uint64_t encrypt(uint64_t w, uint64_t masterKey, int rounds);

uint64_t decrypt(uint64_t w, uint64_t masterKey, int rounds);

void printRelations();

void experiment(int a);

#endif