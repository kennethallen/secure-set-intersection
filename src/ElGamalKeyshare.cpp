#include <cassert>
#include "ElGamal.h"

// DEBUG
#include <iostream>
using std::cout;

namespace ElGamal
{

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
	
	istream& operator>>(istream& in, DecryptShare& share)
	{
		return in >> share.x >> share.share.get_mpz_t();
	}
	
	ostream& operator<<(ostream& out, const DecryptShare& share)
	{
		return out << share.x << ' ' << share.share.get_mpz_t();
	}
	
	DecryptShare Keyshare::decryptShare(const Params& params,
			const Ciphertext& cipher) const
	{
		return DecryptShare(x, params.modExp(cipher.B, y));
	}
	
	mpz_class DecryptShare::lagrangeFactor(const Params& params,
			const vector<DecryptShare>& shares) const
	{
		mpq_class product(1);
		for (auto share : shares)
		{
			if (x == share.x)
				continue;
			product *= share.x;
			product /= (static_cast<int>(share.x) - static_cast<int>(x));
		}
		
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

}