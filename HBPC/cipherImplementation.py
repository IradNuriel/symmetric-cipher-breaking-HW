#code for 256 key and input
import hashlib
import sys


word="0"
key="0"

def prepare_keys(key):#preparing the round keys
    Hash = hashlib.shake_128()
    RoundKeys=[]
    Hash.update(str(key).encode())
    key=int.from_bytes(Hash.digest(10),"little")
    roundkey=key
    for i in range(0,10):
        Hash.update(str(roundkey^key).encode())
        roundkey=int.from_bytes(Hash.digest(10),"little")
        RoundKeys.append(roundkey)
    return RoundKeys

def Expand(word):
    word_new=0
    for i in  range (8):
        nibble = (word  << (i*4)) & 0xF 
        word_new  |= nibble >> 2*i*4
        word_new  |= nibble >> ((2*i*4)+4)
    return  word_new

def Shrink(word):
    first_nibble = word & 0xF
    word_new=0
    for i in  range (8):
        nibble = (word  << (2*i*4)) & 0xF 
        next_nibble=(word  << ((2*i*4)+4)) & 0xF 
        if i==7:
            next_next_nibble= first_nibble
        else:
             next_next_nibble= (word  << ((2*i*4)+8)) & 0xF
        nibble=(nibble|next_nibble)^next_next_nibble
        word_new  |= nibble >> i*4
    return word_new

def EARKS(word,round_key):
    new_word=Expand(word)
    new_word=new_word^(round_key&0xFFFFFFFF)
    new_word=Shrink(new_word)
    return new_word

def  get_rows(word):
    row_0 = (word  >> 48) & 0xFFFF
    row_1 = (word  >> 32) & 0xFFFF
    row_2 = (word  >> 16) & 0xFFFF
    row_3 = (word  >> 0) & 0xFFFF
    return  row_0 , row_1 , row_2 , row_3

def  rotate_left(word , n, word_size =64):
    mask = 2** word_size  - 1
    return  ((word  << n) & mask) | ((word  >> (word_size  - n) & mask))

def  shift_rows(word):
    row_0 , row_1 , row_2 , row_3 = get_rows(word)
    row_0 = row_0
    row_1 = rotate_left(row_1 , 4, 16)
    row_2 = rotate_left(row_2 , 8, 16)
    row_3 = rotate_left(row_3 , 12, 16)
    new_word = row_0  << 48
    new_word  |= row_1  << 32
    new_word  |= row_2  << 16
    new_word  |= row_3  << 0
    return  new_word

def  mix_columns(word):
    row_0 , row_1 , row_2 , row_3 = get_rows(word) 
    new_word = (row_0 ^ row_2) << 48
    new_word  |= (row_1 ^ row_2) << 32
    new_word  |= (row_0 ^ row_3) << 16
    new_word  |= (row_2 ^ row_3) << 0
    return  new_word

def encrypt(word, key, rounds=10):
    RoundKeys=[]
    RoundKeys=prepare_keys(key)
    r=0
    l=0
    for round_number in range(0, rounds):
        r=(word<<32)&0xFFFFFFFF
        l=word&0xFFFFFFFF
        F=EARKS(r,RoundKeys[round_number])
        l=F^l
        F=EARKS(l,RoundKeys[round_number])
        r=r^F
        word=r>>32|l
        word=shift_rows(word)
        word=mix_columns(word)
    
    return word


        



if __name__ == "__main__":
    import sys
    import random

    if len(sys.argv) not in [3, 4]:
        print("Error occured %d"%(len(sys.argv)))
        exit()
    
    key = random.getrandbits(64) #int(sys.argv[1], 16)
    rounds = int(sys.argv[2])
    if len(sys.argv) == 4:
        delta_in = int(sys.argv[3], 16)

    nrof_pairs = 2**10

    #print("# %s %d rounds"%(sys.argv[0], rounds))

    for i in range(nrof_pairs):
        word = random.getrandbits(64)
        cipher = encrypt(word, key, rounds=rounds)
        if len(sys.argv) == 3:
            print("%016X %016X"%(word, cipher))
        else:
            word_2 = word ^ delta_in
            cipher_2 = encrypt(word_2, key, rounds=rounds) 
            print("%016X %016X %016X %016X"%(word, word_2, cipher, cipher_2))
            
    
