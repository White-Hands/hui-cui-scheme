#include<stdio.h>
#include<stdlib.h>
#include<pbc.h>
#include "pbc_inshort.h"
//int Number_of_attribute = 10;
#define  Number_of_attribute 10

struct PublicKey {
	element_t g;
	element_t ga;
	element_t eggalpha;
	element_t hi[Number_of_attribute];
	element_t h;
};

struct MasterSecertKey {
	element_t a;
	element_t alpha;
	element_t galpha;
};

struct UserPrivateKey {
	element_t s;
	element_t sk1_;
	element_t sk1i[Number_of_attribute];
	element_t sk2;
};

struct CipherText {
	element_t C;
	element_t C_;
	element_t Ci[Number_of_attribute];
	element_t Di[Number_of_attribute];
	element_t wi[Number_of_attribute];
	element_t vi[Number_of_attribute];
	element_t u;
};



void Setup(struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing);

void KeyGen (struct UserPrivateKey * sk, struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing);

void Encryption (struct CipherText * CT,struct PublicKey *PK, pairing_t pairing);

void Decrypt(struct CipherText *CT, struct PublicKey * PK,struct UserPrivateKey * sk, pairing_t pairing);
