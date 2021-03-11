#ifndef _CIPHERIMPLEMENTATION_H_
#define _CIPHERIMPLEMENTATION_H_

typedef struct word{
	short nibble[16]
} word;


word keySchdule(word prevKey);

word addRoundKey(word w, word k);

word shiftRowsMixColumns(word w);

word applySbox(word w);

word roundFunction(word w, word k);

word encrypt(word w, word key, int rounds);

#endif