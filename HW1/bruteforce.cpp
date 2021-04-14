#include <iostream>
#include <thread>
#include <vector>
#include <stdint.h>
#include "cipherImplementation.h"


using namespace std;
//the main bruteforce file
bool f = false;



void bf(word plaintext, word ciphertext, word startingPoint, word limit){
	for(word key = startingPoint; key < limit; key++){
		if(f){
			return;
		}
		if(encrypt(plaintext, key, 20)==ciphertext){
			cout << hex << key << endl;
			f = true;
			return;
		}
	}
}



int main(){
	word plaintext = 0xF0B08C0104628B8D;  // the plaintext from the website 
	word ciphertext = 0x9FF50E3992B3B662;  // the ciphertext from the website
	word limit = 1LL<<44;  // maximum key to try
	vector<thread> vec = vector<thread>();
	for(int i = 0; i < 16; i+=1){  // paralleling the attack, so it will take 2^36 instead of 2^40 
 		vec.push_back(thread(bf, plaintext, ciphertext, i * 0x10000000000, limit));
 	}
 	for(auto& t : vec){
 		t.join();
 	}
}