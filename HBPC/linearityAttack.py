from sage.all import *

GF2 = GF(2)

def mkVector(value):
	return list(map(int, '{:064b}'.format(value)))


def getInputs(n, a=False):
	plaintexts = []
	ciphertexts = []
	for i in range(n):
		line = input()
		if not a:
			plaintext  = int(line.split(' ')[0], 16)
			ciphertext = int(line.split(' ')[1], 16)
			plaintexts  = plaintexts  + [plaintext]
			ciphertexts = ciphertexts + [ciphertext]
		if a:
			plaintext1  = int(line.split(' ')[0], 16)
			plaintext2  = int(line.split(' ')[1], 16)
			ciphertext1 = int(line.split(' ')[2], 16)
			ciphertext2 = int(line.split(' ')[3], 16)
			plaintexts = plaintexts + [plaintext1]
			plaintexts = plaintexts + [plaintext2]
			ciphertexts = ciphertexts + [ciphertext1]
			ciphertexts = ciphertexts + [ciphertext2]

	return plaintexts, ciphertexts



def getChallenge(n):
	plaintexts = []
	for i in range(n):
		plaintext = int(input(), 16)
		plaintexts = plaintexts + [plaintext]
	return plaintexts



def getZeroEncryption(plaintexts, ciphertexts, plaintextMatrix, goodCiphertexts):  # find where the xor of ciphertexts don't match the ciphertext, and xor of it with the ciphertext is the encryption of 0
	resp = 0x0000000000000000
	i = 0
	while True:
		pt = plaintexts[i]
		ct = ciphertexts[i]
		resp = 0x0000000000000000
		solvedEquation = plaintextMatrix.solve_right(vector(mkVector(pt)))
		cnt = 0
		for xored, ciphertext in zip(solvedEquation, goodCiphertexts):
			if xored:
				cnt += 1
				resp ^= ciphertext
		if resp != ct:
			resp ^= ct
			break
		i += 1
		if i >= 960:
			print("Can't solve the challenge with the given data.")
			exit()
	return resp






if __name__ == "__main__":  # (the encryption is C=A*PxorX where X is encryption of 0)
	
	plaintexts, ciphertexts = getInputs(1024)  # get the input plaintext ciphertext
	vectors = []
	goodCiphertexts = []
	# loop over some numbers
	for pt, ct in zip(plaintexts[:256], ciphertexts[:256]):
		# generate a 256bit vector from a possible filename
		# create a matrix of all old vectors + the potential new one in GF(2)
		m = matrix(GF2, vectors + [mkVector(pt)]).transpose()
		# check the rank of this matrix
		rank = m.rank()
		# if rank increased, keep this plaintext and ciphertext because it's linear independent
		if rank > len(vectors):
			vectors += [mkVector(pt)]
			goodCiphertexts += [ct]
		if len(vectors)>=64:
			break
	plaintextMatrix = matrix(GF2, vectors).transpose()  # create matrix where the columns are the plaintexts
	#challenges = getChallenge(3)  # getting the challenge which we need to encrypt
	resp = getZeroEncryption(plaintexts, ciphertexts, plaintextMatrix, goodCiphertexts)  # get the encryption on 0 

	for challenge in plaintexts:  # for each challenge
		solvedEquation = plaintextMatrix.solve_right(vector(mkVector(challenge)))  # find which plaintexts we need to xor to get the challenge
		# for each vector we need to xor, we xor(without the offset)
		response = resp
		# print(solvedEquation)
		i=0
		for xored, ciphertext in zip(solvedEquation, goodCiphertexts):
			if xored:
				#print("%016X"%(response))  # print challenge with the response
				response ^= (ciphertext^resp)
			i += 1
		print("%016X %016X"%(challenge, response))  # print challenge with the response



