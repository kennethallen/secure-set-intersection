#include <iostream>
#include "ElGamal.h"

using namespace std;
using namespace ElGamal;

// WolframAlpha: NextPrime[RandomInteger[{2^2047, 2^2048 - 1}]]
const mpz_class examplePrime2048("232694713771420053057630659213799416664731018"
		"9359913423003833628344403322850843540167605845929639947507378497669310"
		"2762094021960948437186598373448972361943112395383369839334032056711919"
		"9920031245087329849131698258142680893603082257798623479652433420482940"
		"3617547495329660017332424979362164574574781241001013805001492416897769"
		"6064860217934423820631768414917668025181498424391491613419411424646499"
		"8299225473626180129133915073742515526257311774033375074610794958570909"
		"7600402059690183762551033097266501366844931910700964368934454192256450"
		"1337067551530076879504006300195645658951599597753082457935644344685069"
		"504949373939");

// WolframAlpha: NextPrime[RandomInteger[{2^511, 2^512 - 1}]]
const mpz_class examplePrime512("1188079157195371837740287837372032314777428766"
		"8030217970706261563262339372869147702623362771035225481725961888214611"
		"801269114442842045500352749369483590123");

// WolframAlpha: NextPrime[RandomInteger[{2^15, 2^16 - 1}]]
const mpz_class examplePrime16(64151);

// WolframAlpha: NextPrime[RandomInteger[{2^7, 2^8 - 1}]]
const mpz_class examplePrime8(149);


void testBasicElGamal(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
	cout << "Enter message (number in range [0, p)): " << flush;
	string token;
	cin >> token;
	const mpz_class msg(token);
	cout << "msg=" << msg.get_str() << "\n\n";
	
	const Ciphertext cipher = pub.encrypt(params, msg, rand);
	cout << "Ciphertext: B=" << cipher.B.get_str()
			<< ", c=" << cipher.c.get_str() << "\n\n";
	
	const mpz_class recoveredMsg = priv.decrypt(params, cipher);
	cout << "recoveredMsg=" << recoveredMsg.get_str() << endl;
}

void testExpElGamal(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
	cout << "Enter message (number in range [0, " << params.modulusBits()
			<< ")): " << flush;
	unsigned msg;
	cin >> msg;
	mpz_class expMsg = powerOf2(msg);
	cout << "msg=" << msg << ", expMsg=" << expMsg.get_str() << "\n\n";
	
	const Ciphertext cipher = pub.encrypt(params, expMsg, rand);
	cout << "Ciphertext: B=" << cipher.B.get_str()
			<< ", c=" << cipher.c.get_str() << "\n\n";
	
	const mpz_class recoveredExpMsg = priv.decrypt(params, cipher);
	const int recoveredMsg = tryLogBase2(params, recoveredExpMsg);
	cout << "recoveredExpMsg=" << recoveredExpMsg.get_str()
			<< ", recoveredMsg=" << recoveredMsg << endl;
}

void testHomomorphicExpElGamal(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
	unsigned addend1, addend2;
	cout << "Enter first addend (number in range [0, " << params.modulusBits()
			<< ")): " << flush;
	cin >> addend1;
	mpz_class expAddend1 = powerOf2(addend1);
	cout << "addend1=" << addend1
			<< ", expAddend1=" << expAddend1.get_str() << "\n\n";
	cout << "Enter second addend (number in range [0, " << params.modulusBits()
			<< ")): " << flush;
	cin >> addend2;
	mpz_class expAddend2 = powerOf2(addend2);
	cout << "addend2=" << addend2
			<< ", expAddend2=" << expAddend2.get_str() << "\n\n";
	
	const Ciphertext cipher1 = pub.encrypt(params, expAddend1, rand),
			cipher2 = pub.encrypt(params, expAddend2, rand);
	cout << "Ciphertext 1: B=" << cipher1.B.get_str()
			<< ", c=" << cipher1.c.get_str() << "\n\n";
	cout << "Ciphertext 2: B=" << cipher2.B.get_str()
			<< ", c=" << cipher2.c.get_str() << "\n\n";
	
	Ciphertext cipherExpSum = cipher1;
	cipherExpSum.mult(params, cipher2);
	cout << "Ciphertext expSum: B=" << cipherExpSum.B.get_str()
			<< ", c=" << cipherExpSum.c.get_str() << "\n\n";
	
	const mpz_class recoveredExpSum = priv.decrypt(params, cipherExpSum);
	const int recoveredSum = tryLogBase2(params, recoveredExpSum);
	cout << "recoveredExpSum=" << recoveredExpSum.get_str()
			<< ", recoveredSum=" << recoveredSum << endl;
}

void testThresholdElGamal(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
	cout << "Enter number of keyshares: " << flush;
	unsigned numKeyshares;
	cin >> numKeyshares;
	cout << "numKeyshares=" << numKeyshares << '\n';
	
	const vector<Keyshare> keyshares = priv.generateShares(params,
			numKeyshares, numKeyshares, rand);
	for (auto share : keyshares)
		cout << "Keyshare: x=" << share.x
				<< ", y=" << share.y.get_str() << '\n';
	cout << '\n';
	
	cout << "Enter message (number in range [0, p)): " << flush;
	string token;
	cin >> token;
	const mpz_class msg(token);
	cout << "msg=" << msg.get_str() << "\n\n";
	
	const Ciphertext cipher = pub.encrypt(params, msg, rand);
	cout << "Ciphertext: B=" << cipher.B.get_str()
			<< ", c=" << cipher.c.get_str() << "\n\n";
	
	vector<DecryptShare> decryptionShares;
	decryptionShares.reserve(keyshares.size());
	for (auto keyshare : keyshares)
	{
		const DecryptShare decryptShare = keyshare.decryptShare(params, cipher);
		cout << "DecryptShare: x=" << decryptShare.x
				<< ", share=" << decryptShare.share.get_str() << '\n';
		decryptionShares.push_back(decryptShare);
	}
	cout << '\n';
	
	const mpz_class recoveredMsg = cipher.decryptWith(params, decryptionShares);
	cout << "recoveredMsg=" << recoveredMsg.get_str() << endl;
}

int testThresholdElGamalErrorIter(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
//	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
//	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
//	cout << "Enter number of keyshares: " << flush;
	unsigned numKeyshares;
//	cin >> numKeyshares;
//	cout << "numKeyshares=" << numKeyshares << '\n';
	numKeyshares = 3;
	
	const vector<Keyshare> keyshares = priv.generateShares(params,
			numKeyshares, numKeyshares, rand);
//	for (auto share : keyshares)
//		cout << "Keyshare: x=" << share.x
//				<< ", y=" << share.y.get_str() << '\n';
//	cout << '\n';
	
//	cout << "Enter message (number in range [0, p)): " << flush;
//	string token;
//	cin >> token;
//	const mpz_class msg(token);
//	cout << "msg=" << msg.get_str() << "\n\n";
	const mpz_class msg(1);
	
	const Ciphertext cipher = pub.encrypt(params, msg, rand);
//	cout << "Ciphertext: B=" << cipher.B.get_str()
//			<< ", c=" << cipher.c.get_str() << "\n\n";
	
	vector<DecryptShare> decryptionShares;
	decryptionShares.reserve(keyshares.size());
	for (auto keyshare : keyshares)
	{
		const DecryptShare decryptShare = keyshare.decryptShare(params, cipher);
//		cout << "DecryptShare: x=" << decryptShare.x
//				<< ", share=" << decryptShare.share.get_str() << '\n';
		decryptionShares.push_back(decryptShare);
	}
//	cout << '\n';
	
	const mpz_class recoveredMsg = cipher.decryptWith(params, decryptionShares);
//	cout << "recoveredMsg=" << recoveredMsg.get_str() << endl;
	
	if (recoveredMsg == 1)
		return 0;
	for (int i = 1; ; i++) {
		if (recoveredMsg == params.modExp(cipher.B, i))
			return i;
		if (recoveredMsg == params.modExp(cipher.B, mpz_class(-i)))
			return -i;
	}
}

void testThresholdElGamalError(const Params& params, gmp_randclass& rand)
{
	unsigned hist[7] = {};
	for (unsigned i = 0; i < 10000; i++)
	{
		const int error = testThresholdElGamalErrorIter(params, rand);
		cout << error << ' ';
		if (i % 100 == 0)
			cout << flush;
		
		if (abs(error) > 3)
			break;
		hist[error + 3]++;
	}
	cout << '\n';
	for (auto freq : hist)
		cout << freq << ' ';
	
	cout << endl;
}

int main() {
	gmp_randclass rand(gmp_randinit_default);
	rand.seed(time(nullptr));
	
	const mpz_class p = examplePrime512;
	const mpz_class g = rand.get_z_range(p - 3) + 2;
	const Params params(p, g);
	cout << "Params: g=" << params.g.get_str()
			<< ", p=" << params.p.get_str() << "\n\n";
	
	testThresholdElGamalError(params, rand);
	
	return 0;
}