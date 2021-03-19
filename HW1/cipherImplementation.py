#!/usr/bin/env python3

def rotate_left(word, n, word_size=64):
    mask = 2**word_size - 1
    return ((word << n) & mask) | ((word >> (word_size - n) & mask)) 

def L(word):
    return (rotate_left(word, 15) ^ rotate_left(word, 32) ^ word)

def apply_sbox(word, sbox):
    # apply the sbox to every nibble
    word_new = 0

    for i in range(16): # 16 nibbles
        nibble = (word >> (i*4)) & 0xF # retrieve the ith nibble
        # insert the permuted nibble in the correct position
        word_new |= sbox[nibble] << i*4 
    return word_new

def round_function(word, key):
    # we first define the S-box, now sbox[0] = 2, sbox[1] = 4, etc.
    sbox = [0x2, 0x4, 0x5, 0x6, 0x1, 0xA, 0xF, 0x3, 
            0xB, 0xE, 0x0, 0x7, 0x9, 0x8, 0xC, 0xD]

    # xor the key into the state
    word ^= key
    # apply the sbox to every nibble of the word
    word = apply_sbox(word, sbox)
    # apply the linear layer to the state
    word = L(word)
    # return the new word and the key for the next round
    return word, L(key)^0x3

def encrypt(word, key, rounds=20):
    # Apply the round function <rounds> times
    for r in range(rounds):
        word, key = round_function(word, key)
    
    return word


