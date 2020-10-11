#include "src/pbc_inshort.h"
#include "src/hui-cui.h"


int main(){
	pairing_t pairing;
	init_pairing(pairing);	
	if(pairing_is_symmetric(pairing)==1)
		puts("This is a symmetric group");
	else
		puts("This is a asymmetric group");


	/* KGC */
	struct PublicKey PK;
	struct MasterSecertKey msk;
	Setup(&PK, &msk, pairing);

	/* KGC */
	struct UserPrivateKey sk;
	KeyGen(&sk, &PK, &msk, pairing);
	
	/* Owner*/
	struct CipherText CT;
	Encryption(&CT, &PK, pairing);
	
	/* User*/
	Decrypt(&CT, &PK, &sk, pairing);


	return 0;
}

