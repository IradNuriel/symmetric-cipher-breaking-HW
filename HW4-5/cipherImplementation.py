#!/usr/bin/env python3

def apply_sbox(word, nibbles=4):
    """ apply the sbox to every nibble """
    word_new = 0
    sbox = (0xE, 0xB, 4, 6, 0xA, 0xD, 7, 0, 3, 8, 0xF, 0xC, 5, 9, 1, 2)
    for i in range(nibbles): # 16 nibbles
        nibble = (word >> (i*4)) & 0xF # retrieve the ith nibble
        # insert the permuted nibble in the correct position
        word_new |= sbox[nibble] << i*4 
    return word_new

def sigma(word):
    """
    Implementing the sigma permutation on the 8 bit word.
    """
    new_word = 0
    # first move the two most significant bits of nibble 0 and 3 
    new_word |= (word & 0b1100000000001100) >> 1 # 0, 1, C, D

    # now move the rest of the bits 
    new_word |= (word & 0x2000) >> 6 # 2
    new_word |= (word & 0x1000) >> 8 # 3
    new_word |= (word & 0x0C00) >> 5 # 4, 5
    new_word |= (word & 0x0200) << 6 # 6
    new_word |= (word & 0x0100) << 4 # 7
    new_word |= (word & 0x00C0) << 3 # 8, 9
    new_word |= (word & 0x0020) >> 2 # A
    new_word |= (word & 0x0010) >> 4 # B
    new_word |= (word & 0x0002) << 10 # E
    new_word |= (word & 0x0001) << 8 # E

    return new_word

def F(word):
    return sigma(apply_sbox(word))

def round_function(left, right, key):
    return ((F(left) ^ right ^ key), left)
     
def compute_roundkeys(key, rounds):
    key_parts = []
    for i in range(4):
        key_parts.append(key & 0xFFFF)
        key >>= 16
    # Most significant part should be on index 0
    key_parts.reverse() 

    for i in range(4, rounds):
        rk = key_parts[i-4] ^ key_parts[i-1] ^ sigma(key_parts[i-2]) ^ 0xC
        key_parts.append(rk)
    
    return key_parts

def encrypt(word, key, rounds=16):
    left = (word >> 16) & 0xFFFF
    right = word & 0xFFFF

    round_keys = compute_roundkeys(key, rounds)

    for i in range(rounds):
        left, right = round_function(left, right, round_keys[i])

    return (left << 16) | right

def decrypt(word, key, rounds=16):
    left = word & 0xFFFF
    right = (word >> 16) & 0xFFFF
    
    round_keys = compute_roundkeys(key, rounds)
    round_keys.reverse()

    for i in range(rounds):
        left, right = round_function(left, right, round_keys[i])

    return (right << 16) | left