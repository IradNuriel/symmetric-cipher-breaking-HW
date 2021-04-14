#!/usr/bin/env python3
"""
    A very slow implementation of TC02

    64 bit state divided in 16 4-bit nibbles arranged in a matrix representation

    F E D C -> row_0
    B A 9 8 -> row_1
    7 6 5 4 -> row_2
    3 2 1 0 -> row_3

    Round function:
      add roundkey
      S-layer [same as TC01]
      AES shift rows (0, 1, 2, 3)
      Mix Columns:
      1 0 1 0
      0 1 1 0
      1 0 0 1
      0 0 1 0
    
    Key expansion:
        The Key has a 64-bit state like the cipher state. Keystate in round i 
        K_i is computed as follows.
        
        K_{i+1} = (K_{i} ^ 0x3) >>> 16      # the rotation is given in bits
        
        The round key in the i-th round is given by:
        k_i = K{i} & 0xFFFFFFFF00000000     # mask the two most significant rows
"""
def get_rows(word):
    row_0 = (word >> 48) & 0xFFFF 
    row_1 = (word >> 32) & 0xFFFF
    row_2 = (word >> 16) & 0xFFFF
    row_3 = (word >> 0) & 0xFFFF
    return row_0, row_1, row_2, row_3

def rotate_left(word, n, word_size=64):
    mask = 2**word_size - 1
    return ((word << n) & mask) | ((word >> (word_size - n) & mask)) 

def rotate_right(word, n, word_size=64):
    mask = 2**word_size - 1
    return ((word >> n) & mask) | ((word << (word_size - n) & mask)) 

def next_keystate(keystate):
    return rotate_right(keystate ^ 0x3, 16, 64)

def add_roundkey(word, keystate):
    return word ^ (keystate & 0xFFFFFFFF00000000)

def apply_sbox(word, sbox):
    """ apply the sbox to every nibble """
    word_new = 0
    for i in range(16): # 16 nibbles
        nibble = (word >> (i*4)) & 0xF # retrieve the ith nibble
        # insert the permuted nibble in the correct position
        word_new |= sbox[nibble] << i*4 
    return word_new

def shift_rows(word):
    row_0, row_1, row_2, row_3 = get_rows(word)
    
    # apply the shiftrows transformation
    row_0 = row_0 
    row_1 = rotate_left(row_1, 4, 16)
    row_2 = rotate_left(row_2, 8, 16) 
    row_3 = rotate_left(row_3, 12, 16) 
    
    # reconstruct the word
    new_word = row_0 << 48      # a |= b <==> a = a | b
    new_word |= row_1 << 32
    new_word |= row_2 << 16
    new_word |= row_3 << 0
    
    return new_word

def mix_columns(word):
    row_0, row_1, row_2, row_3 = get_rows(word) # split up the word into rows
    # Apply the mix culomns transformation and reconstruct the word
    new_word = (row_0 ^ row_2) << 48
    new_word |= (row_1 ^ row_2) << 32   # a |= b <==> a = a | b
    new_word |= (row_0 ^ row_3) << 16
    new_word |= row_2 << 0
    
    return new_word

def round_function(word, keystate):
    sbox = [0x2, 0x4, 0x5, 0x6, 0x1, 0xA, 0xF, 0x3, 
            0xB, 0xE, 0x0, 0x7, 0x9, 0x8, 0xC, 0xD]
    
    word = add_roundkey(word, keystate)
    word = apply_sbox(word, sbox)
    word = shift_rows(word)
    word = mix_columns(word)
    
    return word

def encrypt(word, key, rounds=8):
    keystate = key
    for i in range(rounds):
        # apply the roundfunction to word 
        word = round_function(word, keystate)
        # go to the next key state
        keystate = next_keystate(keystate)
    return word

if __name__ == "__main__":
    import sys
    import random

    for i in range(16):
    	print("%01X"%(sboxDec[sboxEnc[i]]),end=" ")
    key = 0
    ws = [0xCEED2282E7F5BBCA, 0x5A5326531BB5466D, 0x12304A327FA00607, 0x0A8BBD595AC8241F, 0x7697287878A19C36, 0x8B965C07A99237B5, 0x6ECCA7F3867340EA, 0xA0D352D5470CAC88, 0x10B5756644C06441, 0x70A8B346A0CFB098, 0xDB0A99C216D6E5F8, 0x686709BF3723E147, 0xA16FADCEE0544335, 0x19C815648F874398, 0x05D4B6F045B9C45F, 0x789ABDAAFD2191CE, 0xFCC7EB50A0044370, 0xC1A85A3B0DA0BC36, 0x246E7EB0C6B83A2E, 0xC981452CFAF603E4, 0xBF0BE44896AE633B, 0x05FB0E18D7805917, 0x534364CC07B0B661, 0xEBECDE713A0E446D, 0x1799D7D64FBB0D0B, 0x6E5889E42324D403, 0xF4406CFDDAA47830, 0xF2D3F7291940A397, 0x94B6C451F0AF5733, 0x1DBFF310D1B99A86, 0xD2684240AF802634, 0x7483302A2E7BA25B]
    for i in range(32):
        word = ws[i]
        cipher = encrypt(word, key, rounds=8)
        print("%016X %016X"%(word, cipher))