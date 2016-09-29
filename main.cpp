#include <iostream>
#include "ElGamal.h"

using namespace std;
using namespace ElGamal;

// Generated via WolframAlpha with query
// NextPrime[RandomInteger[{2^2047, 2^2048 - 1}]]
const mpz_class examplePrime2048("2326947137714200530576306592137994166647"
		"31018935991342300383362834440332285084354016760584592963994750737"
		"84976693102762094021960948437186598373448972361943112395383369839"
		"33403205671191999200312450873298491316982581426808936030822577986"
		"23479652433420482940361754749532966001733242497936216457457478124"
		"10010138050014924168977696064860217934423820631768414917668025181"
		"49842439149161341941142464649982992254736261801291339150737425155"
		"26257311774033375074610794958570909760040205969018376255103309726"
		"65013668449319107009643689344541922564501337067551530076879504006"
		"300195645658951599597753082457935644344685069504949373939");
// Generated via WolframAlpha with query
// NextPrime[RandomInteger[{2^15, 2^16 - 1}]]		
const mpz_class examplePrime16(64151);

void testBasicElGamal(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
	cout << "Enter msg (number in range [0, p)): " << flush;
	string line;
	getline(cin, line);
	const mpz_class msg(line);
	cout << "msg=" << msg.get_str() << "\n\n";
	
	const Ciphertext cipher = pub.encrypt(params, msg, rand);
	cout << "Ciphertext: B=" << cipher.B.get_str()
			<< ", c=" << cipher.c.get_str() << "\n\n";
	
	const mpz_class recoveredMessage = priv.decrypt(params, cipher);
	cout << "recoveredMessage=" << recoveredMessage.get_str() << endl;
}

void testExpElGamal(const Params& params, gmp_randclass& rand)
{
	const KeyPair keyPair = params.makeKeys(rand);
	const PrivateKey priv = get<PrivateKey>(keyPair);
	const PublicKey pub = get<PublicKey>(keyPair);
	cout << "PrivateKey: a=" << priv.a.get_str() << "\n\n";
	cout << "PublicKey: A=" << pub.A.get_str() << "\n\n";
	
	cout << "Enter msg (number in range [0, " << params.modulusBits()
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
	
	const vector<Keyshare> keyshares = priv.generateShares(params, 3, rand);
	for (auto share : keyshares)
		cout << "Keyshare: x=" << share.x
				<< ", y=" << share.y.get_str() << '\n';
	cout << '\n';
	
	cout << "Enter msg (number in range [0, p)): " << flush;
	string line;
	getline(cin, line);
	const mpz_class msg(line);
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
	cout << "recoveredMessage=" << recoveredMsg.get_str() << endl;
}

int main() {
	gmp_randclass rand(gmp_randinit_default);
	rand.seed(time(nullptr));
	
	const mpz_class p = examplePrime16;
	const mpz_class g = rand.get_z_range(p - 3) + 2;
	const Params params(p, g);
	cout << "Params: g=" << params.g.get_str()
			<< ", p=" << params.p.get_str() << "\n\n";
	
	testThresholdElGamal(params, rand);
	
	return 0;
}