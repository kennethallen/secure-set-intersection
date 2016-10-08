#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <vector>
#include "gmpxx.h"

using std::move;
using std::vector;

namespace ElGamal {
	
	// The 2048-bit prime suggested for use in Diffie-Helman by RFC 3526,
	// with generator 2.
	const mpz_class prime2048rfc3526("0x"
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	)
	
	class Params;
	class PublicKey;
	class PrivateKey;
	typedef std::pair<PrivateKey, PublicKey> KeyPair;
	class DecryptShare;

	mpz_class powerOf2(unsigned);
	int tryLogBase2(const mpz_class&, unsigned low, unsigned high);
	int tryLogBase2(const Params&, const mpz_class&);

	class Params
	{
	public:
		mpz_class p; // safe prime modulus
		mpz_class g; // group generator

		Params(mpz_class _p, mpz_class _g) : p(move(_p)), g(move(_g)) { }
		unsigned modulusBits() const;
		KeyPair makeKeys(gmp_randclass&) const;
		mpz_class modExp(const mpz_class& base, const mpz_class& pow) const;
		mpz_class modExp(const mpz_class& base, unsigned pow) const;
		mpz_class modInv(const mpz_class&) const;
	};

	class Ciphertext
	{
	public:
		mpz_class B; // g^(msg secret b)
		mpz_class c; // msg * g^(a * b)
		
		Ciphertext(mpz_class _B0, mpz_class _c) : B(move(_B0)), c(move(_c)) { }
		void mult(const Params&, const mpz_class& plaintextFactor);
		void mult(const Params&, const Ciphertext& ciphertextFactor);
		void pow(const Params&, unsigned power);
		void encryptPrecomputed(const Params&, const mpz_class& msg);
		
		mpz_class decryptWith(const Params&,
				const vector<DecryptShare>&) const;
	};

	class PublicKey
	{
	public:
		mpz_class A; // g^(secret a)

		PublicKey(mpz_class _A) : A(move(_A)) { }
		Ciphertext compute(const Params&, gmp_randclass&) const;
		Ciphertext encrypt(const Params&,
				const mpz_class& msg, gmp_randclass&) const;
	};
	
	class DecryptShare
	{
	public:
		unsigned x; // x of Shamir coordinate
		mpz_class share; // B^(keyshare's y) mod p
		
		DecryptShare(unsigned _x, mpz_class _s) : x(_x), share(move(_s)) { }
		mpz_class lagrangeFactor(const Params&,
				const vector<DecryptShare>&) const;
	};
	
	class Keyshare
	{
	public:
		unsigned x; // x of Shamir coordinate
		mpz_class y; // y of Shamir coordinate
		
		Keyshare(unsigned _x, mpz_class _y) : x(_x), y(move(_y)) { }
		DecryptShare decryptShare(const Params&, const Ciphertext&) const;
	};
	
	class PrivateKey
	{
	public:
		mpz_class a; // secret

		PrivateKey(mpz_class _a) : a(move(_a)) { }
		mpz_class decrypt(const Params&, const Ciphertext&) const;
		vector<Keyshare> generateShares(const Params&, unsigned threshold,
				unsigned numShares, gmp_randclass&) const;
	};

}

#endif