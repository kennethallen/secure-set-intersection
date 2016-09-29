#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <vector>
#include "gmpxx.h"

using std::move;
using std::vector;

namespace ElGamal {
	
	class Params;
	class PublicKey;
	class PrivateKey;
	typedef std::pair<PrivateKey, PublicKey> KeyPair;
	class DecryptShare;

	mpz_class powerOf2(const unsigned);
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
		mpz_class modExp(const mpz_class& base, const unsigned pow) const;
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
		void pow(const Params&, const unsigned power);
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
		long lagrangeFactor(const Params&, const vector<DecryptShare>&) const;
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
		vector<Keyshare> generateShares(const Params&,
				const unsigned num, gmp_randclass&) const;
	};

}

#endif