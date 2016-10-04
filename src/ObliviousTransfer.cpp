#include <cassert>
#include <sstream>
#include "ObliviousTransfer.h"

using namespace std;

namespace ObliviousTransfer
{
	
	void Client::oblivSend1of2(const unsigned i0, const unsigned i1,
			gmp_randclass& rand)
	{
		string msgType;
		Ciphertext cipherSelection;
		{
			const string selectionBitMsg = in->take();
			istringstream stream(selectionBitMsg);
			
			stream >> msgType >> cipherSelection;
		}
		
		assert(msgType == string("SelectionBit"));
		
		cipherSelection.pow(*params, i1 - i0);
		cipherSelection.mult(*params, publicKey->encrypt(*params,
				powerOfTwo(i0), rand));
		// Necessary?
		cipherSelection.mult(*params, publicKey->compute(*params, rand));
		
		const DecryptShare share = keyshare.decryptShare(*params, cipherSelection);
		
		{
			string selectionMsg;
			ostringstream stream(selectionMsg);
			
			stream << "Selection " << cipherSelection << ' ' << share;
			out->offer(selectionMsg);
		}
		
		// TODO: Receive and confirm commitment
	}
	
	unsigned Client::oblivRecv1of2(const bool selectionBit, gmp_randclass& rand)
	{
		{
			string selectionBitMsg;
			ostringstream stream(selectionBitMsg);
			
			stream << "SelectionBit ";
			const Ciphertext cipherSelection = publicKey->encrypt(*params,
					powerOfTwo(selectionBit ? 0 : 1), rand);
			stream << cipherSelection;
			
			out->offer(selectionBitMsg);
		}
		
		{
			const string selectionMsg = in->take();
			istringstream stream(selectionMsg);
			
			string msgType;
			Ciphertext cipherSelection;
			DecryptShare otherShare;
			stream >> msgType >> cipherSelection >> otherShare;
			
			assert(msgType == string("Selection"));
			
			return tryLogBase2(*params,
				cipherSelection.decryptWith(*params,
					vector<DecryptShare>({ otherShare,
						keyShare.decryptShare(*params, cipherSelection) })));
		}
	}
	
}