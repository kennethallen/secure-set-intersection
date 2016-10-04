#ifndef OBLIVIOUSTRANSFER_H
#define OBLIVIOUSTRANSFER_H

#include <memory>
#include "Buffer.h"
#include "ElGamal.h"

using std::string;
using std::shared_ptr;
using namespace ElGamal;

namespace ObliviousTransfer
{
	
	typedef Buffer<string> Channel;
	
	class Client
	{
		const Params* params;
		const PublicKey* publicKey;
		Keyshare keyshare;
		
		shared_ptr<Channel> in, out;
		
		void oblivSend1of2(unsigned i0, unsigned i1, gmp_randclass&);
		unsigned oblivRecv1of2(bool selectionBit, gmp_randclass&);
	};
	
}

#endif