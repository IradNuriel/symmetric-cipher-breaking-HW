#!/usr/bin/env python3
"""
    A very slow implementation of TC07

    Author: Eran Lambooij
"""


def get_rows(word):
    row_0 = (word >> 48) & 0xFFFF
    row_1 = (word >> 32) & 0xFFFF
    row_2 = (word >> 16) & 0xFFFF
    row_3 = (word >> 0) & 0xFFFF
    return row_0, row_1, row_2, row_3


def rotate_left(word, n, word_size=64):
    mask = 2 ** word_size - 1
    return ((word << n) & mask) | ((word >> (word_size - n) & mask))


def rotate_right(word, n, word_size=64):
    mask = 2 ** word_size - 1
    return ((word >> n) & mask) | ((word << (word_size - n) & mask))


def next_keystate(keystate):
    return rotate_right(keystate ^ 0xF3F3, 16, 64)


def add_roundkey(word, keystate):
    return word ^ (keystate & 0x00000000FFFFFFFF)


def apply_sbox(word):
    """ apply the sbox to every nibble """
    word_new = 0
    sbox = [0xA, 0x5, 0x4, 0x2, 0x6, 0x1, 0xF, 0x3, 0xB, 0xE, 0x7, 0x0, 0x8, 0xD, 0xC, 0x9]
    for i in range(16):  # 16 nibbles
        nibble = (word >> (i * 4)) & 0xF  # retrieve the ith nibble
        # insert the permuted nibble in the correct position
        word_new |= sbox[nibble] << i * 4
    return word_new


def shift_rows(word):
    row_0, row_1, row_2, row_3 = get_rows(word)

    # apply the shiftrows transformation
    row_0 = row_0
    row_1 = rotate_left(row_1, 4, 16)
    row_2 = rotate_left(row_2, 8, 16)
    row_3 = rotate_left(row_3, 12, 16)

    # reconstruct the word
    new_word = row_0 << 48  # a |= b <==> a = a | b
    new_word |= row_1 << 32
    new_word |= row_2 << 16
    new_word |= row_3 << 0

    return new_word


def mix_columns(word):
    row_0, row_1, row_2, row_3 = get_rows(word)  # split up the word into rows
    # Apply the mix culomns transformation and reconstruct the word
    new_word = (row_0 ^ row_2) << 48
    new_word |= (row_1 ^ row_2) << 32  # a |= b <==> a = a | b
    new_word |= (row_0 ^ row_3) << 16
    new_word |= (row_2 ^ row_3) << 0

    return new_word


def round_function(word, keystate):
    word = add_roundkey(word, keystate)
    word = apply_sbox(word)
    word = shift_rows(word)
    word = mix_columns(word)

    return word


def encrypt(word, key, rounds=10):
    keystate = key
    for i in range(rounds):
        # apply the roundfunction to word
        word = round_function(word, keystate)
        # go to the next key state
        keystate = next_keystate(keystate)
    return word


def create_test_vectors():
    state = 0xFEDCBA9800000000
    first_roundkey = 0x01234567

    print("%016X" % state)

    state = add_roundkey(state, first_roundkey)
    print("%016X" % state)

    state = apply_sbox(state)
    print("%016X" % state)

    state = shift_rows(state)
    print("%016X" % state)

    state = mix_columns(state)
    print("%016X" % state)

    print("%016X" % 0, "%016X" % 0, "%016X" % encrypt(0, 0))
    print("%016X" % 42, "%016X" % 1, "%016X" % encrypt(42, 1))
    print("%016X" % 0, "%016X" % 0x0123456789ABCDEF,
          "%016X" % encrypt(0, 0x0123456789ABCDEF))


if __name__ == "__main__":
    import sys
    import hashlib
    import random

    if len(sys.argv) == 1:
        create_test_vectors()
        print("Error occured")
        exit()

    key = int(sys.argv[1], 16)
    # We seed the random generator with a hash of the key to get the same messages for the same key
    random.seed(hashlib.sha256(sys.argv[1].encode()).digest())

    for i in range(16):
        word = random.getrandbits(64)
        cipher = encrypt(word, key, rounds=4)
        print("%016X %016X" % (word, cipher))