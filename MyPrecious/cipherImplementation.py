#!/usr/bin/env python3

mask = 0xFFFFFFFF


def rotate_left(word, n):
    return ((word << n) & mask) | (word >> (32 - n) & mask)


def key_schedule(master_key, nrof_rounds):
    round_keys = [master_key & mask, (master_key >> 32) & mask]
    for i in range(nrof_rounds - 2):
        round_keys.append(
            round_keys[-1] ^ rotate_left(round_keys[-2], 7) ^ 0xFF ^ i
        )
        # print("%016X"%(round_keys[-1]))
    return round_keys


def f_function(word):
    word_2 = word | rotate_left(word, 3)
    return (rotate_left(word, 8) + word_2) & mask


def encrypt(word, master_key, number_rounds=23):
    round_keys = key_schedule(master_key, number_rounds)
    left = word & mask
    right = (word >> 32) & mask

    for i in range(number_rounds):
        swap = left
        left ^= round_keys[i]
        left = f_function(left)
        left = right ^ left
        right = swap
    return (right << 32) | left


def decrypt(word, master_key, number_rounds=23):
    round_keys = key_schedule(master_key, number_rounds)
    right = word & mask
    left = (word >> 32) & mask

    for i in range(number_rounds):
        swap = left
        left ^= round_keys[-(i + 1)]
        left = f_function(left)
        left = right ^ left
        right = swap
    return (left << 32) | right



def create_test_vectors():
    print("%016X" % 0, "%016X" % 0, "%016X" % encrypt(0, 0))
    print("%016X" % 0x42, "%016X" % 0x1, "%016X" % encrypt(0x42, 0x1))
    print("%016X" % 0x0123456789ABCDEF, "%016X" % 0x00000000FEDCBA98, "%016X" % encrypt(0x0123456789ABCDEF, 0x00000000FEDCBA98))
    # encrypt(0x0123456789ABCDEF, 0x00000000FEDCBA98)


if __name__ == "__main__":

    import sys
    import random

    if len(sys.argv) not in [3, 4]:
        create_test_vectors()
        # print("Error occured %d"%(len(sys.argv)))
        exit()
    
    key = int(sys.argv[1], 16)
    rounds = int(sys.argv[2])
    if len(sys.argv) == 4:
        delta_in = int(sys.argv[3], 16)

    nrof_pairs = 2**10

    print("# %s %d rounds"%(sys.argv[0], rounds))

    for i in range(nrof_pairs):
        word = random.getrandbits(64)
        cipher = encrypt(word, key, number_rounds=rounds)
        if len(sys.argv) == 3:
            print("%016X %016X"%(word, cipher))
        else:
            word_2 = word ^ delta_in
            cipher_2 = encrypt(word_2, key, number_rounds=rounds) 
            print("%016X %016X %016X %016X"%(word, word_2, cipher, cipher_2,))
