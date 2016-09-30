#include <cassert>
#include "ElGamal.h"

namespace ElGamal {
	
	mpz_class powerOf2(const unsigned pow)
	{
		mpz_class out;
		mpz_ui_pow_ui(out.get_mpz_t(), 2, pow);
		return out;
	}
	
	int tryLogBase2(const Params& params, const mpz_class& n)
	{
		return tryLogBase2(n, 0, params.modulusBits());
	}
	
	int tryLogBase2(const mpz_class& n, unsigned low, unsigned high)
	{
		// Find the discrete logarithm.  This method only performs a binary
		// search in the range [low, high).
		while (high > low)
		{
			const unsigned current = (high + low) >> 1;
			const mpz_class currentPow = powerOf2(current);
			
			const int compare = cmp(currentPow, n);
			if (compare < 0)
				low = current + 1;
			else if (compare > 0)
				high = current;
			else
				return current;
		}
		
		return -1;
	}
	
	unsigned Params::modulusBits() const
	{
		return mpz_sizeinbase(p.get_mpz_t(), 2);
	}
	
	mpz_class Params::modExp(const mpz_class& base, const mpz_class& pow) const
	{
		mpz_class out;
#ifdef secure_exponentiation
		if (pow >= 0)
		{
			mpz_powm_sec(
					out.get_mpz_t(), base.get_mpz_t(),
					pow.get_mpz_t(), p.get_mpz_t());
		}
		else
		{ // mpz_powm_sec does not support negative exponents.
			mpz_powm_sec(
					out.get_mpz_t(), base.get_mpz_t(),
					mpz_class(-pow).get_mpz_t(), p.get_mpz_t());
			out = modInv(out);
		}
#else
		mpz_powm(
				out.get_mpz_t(), base.get_mpz_t(),
				pow.get_mpz_t(), p.get_mpz_t());
#endif
		
		return out;
	}
	
	mpz_class Params::modExp(const mpz_class& base, const unsigned pow) const
	{
		mpz_class out;
#ifdef secure_exponentiation
		mpz_powm_sec(
				out.get_mpz_t(), base.get_mpz_t(),
				mpz_class(pow).get_mpz_t(), p.get_mpz_t());
#else
		mpz_powm_ui(
				out.get_mpz_t(), base.get_mpz_t(),
				pow, p.get_mpz_t());
#endif
		
		return out;
	}
	
	mpz_class Params::modInv(const mpz_class& n) const
	{
		mpz_class out;
#if NDEBUG
		mpz_invert( out.get_mpz_t(), n.get_mpz_t(), p.get_mpz_t());
#else
		assert(0 != mpz_invert(out.get_mpz_t(), n.get_mpz_t(), p.get_mpz_t()));
#endif
		return out;
	}
	
	KeyPair Params::makeKeys(gmp_randclass& rand) const
	{
		// Secret in range [0, p-2].
		mpz_class a = rand.get_z_range(p - 1);
		
		// A = g^a mod p
		return std::make_pair(PrivateKey(std::move(a)), PublicKey(modExp(g, a)));
	}
	
	void Ciphertext::mult(const Params& params, const mpz_class& plainFactor)
	{
		c *= plainFactor;
		c %= params.p;
	}
	
	void Ciphertext::mult(const Params& params, const Ciphertext& cipherFactor)
	{
		B *= cipherFactor.B;
		B %= params.p;
		
		c *= cipherFactor.c;
		c %= params.p;
	}
	
	void Ciphertext::pow(const Params& params, const unsigned power)
	{
		B = params.modExp(B, power);
		c = params.modExp(c, power);
	}
	
	void Ciphertext::encryptPrecomputed(const Params& params,
			const mpz_class& msg)
	{
		mult(params, msg);
	}
	
	Ciphertext PublicKey::compute(const Params& params,
			gmp_randclass& rand) const
	{
		// Message secret in range [0, p-2].
		mpz_class b = rand.get_z_range(params.p - 1);
		
		// B = g^b mod p
		// c = msg * (A^b = g^(ab)) mod p
		return Ciphertext(params.modExp(params.g, b), params.modExp(A, b));
	}

	Ciphertext PublicKey::encrypt(const Params& params,
			const mpz_class& msg, gmp_randclass& rand) const
	{
		Ciphertext c = compute(params, rand);
		c.encryptPrecomputed(params, msg);
		return c;
	}
	
	mpz_class PrivateKey::decrypt(const Params& params,
			const Ciphertext& cipher) const
	{
		// msg = (c / (g^ab) = c * g^(-ab) = c * B^-a) mod p
		return (cipher.c * params.modExp(cipher.B, -a)) % params.p;
	}
	
}
	#include <iostream>
	using std::cout;
	using std::endl;
namespace ElGamal {
	vector<Keyshare> PrivateKey::generateShares(const Params& params,
			const unsigned threshold, const unsigned numShares,
			gmp_randclass& rand) const
	{
		vector<mpz_class> coeffs;
		coeffs.reserve(threshold - 1);
		for (unsigned pow = 1; pow < threshold; pow++)
			coeffs.emplace_back(rand.get_z_range(params.p));
		
		vector<Keyshare> shares;
		coeffs.reserve(numShares);
		for (unsigned x = 1; x <= numShares; x++)
		{
			mpz_class y = a;
			// DEBUG
//			cout << "x^0 * " << y.get_str() << " = " << y.get_str() << '\n';
			for (unsigned pow = 1, xPow = x;
					pow <= coeffs.size();
					pow++, xPow *= x)
					{
				y += coeffs[pow - 1] * xPow;
						// DEBUG
//						cout << "+(x^" << pow << " * " << coeffs[pow - 1].get_str()
//								<< " = " << mpz_class(coeffs[pow - 1] * xPow).get_str()
//								<< ") = " << y.get_str() << '\n';
					}
				
			shares.emplace_back(Keyshare(x, y % params.p));
		}
		return shares;
	}
	
	mpz_class DecryptShare::lagrangeFactor(const Params& params,
			const vector<DecryptShare>& shares) const
	{
		mpq_class product(1);
		for (auto share : shares)
		{
			if (x == share.x)
				continue;
			product *= mpq_class(share.x,
					static_cast<int>(share.x) - static_cast<int>(x));
		}
		
		product.canonicalize();
		assert(product.get_den() == 1);
		return product.get_num();
	}
	
	mpz_class Ciphertext::decryptWith(const Params& params,
			const vector<DecryptShare>& shares) const
	{
		// g^ab, calculated as the product of keyshares ^ Lagrange factor.
		mpz_class AB(1);
		for (auto share : shares)
		{
			AB *= params.modExp(share.share,
					share.lagrangeFactor(params, shares));
		}
		return (c * params.modInv(AB)) % params.p;
	}
	
	DecryptShare Keyshare::decryptShare(const Params& params,
			const Ciphertext& cipher) const
	{
		return DecryptShare(x, params.modExp(cipher.B, y));
	}

}