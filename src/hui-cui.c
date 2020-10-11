#include "hui-cui.h"
//int Number_of_attribute = 10;

void Setup(struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing){
	/*init msk*/
	/* g */
	G1(PK->g,pairing);

	/* a */
	Zr(msk->a,pairing);

	/* alpha */
	Zr(msk->alpha,pairing);

	/* galpha */
	G1(msk->galpha,pairing);
	element_pow_zn(msk->galpha,PK->g,msk->alpha);

	/*init PK*/	
	/* ga */
	G1(PK->ga,pairing);
	element_pow_zn(PK->ga,PK->g,msk->a);

	/*eggalpha*/
	GT(PK->eggalpha,pairing);
	element_pairing(PK->eggalpha,PK->g,PK->g);
	element_pow_zn(PK->eggalpha,PK->eggalpha,msk->alpha);

	/* h */
	G1(PK->h,pairing);

	/* hi */
	for(int i=0;i<Number_of_attribute;i++){
		G1(PK->hi[i],pairing);
	}

	puts("Setup");

}

void KeyGen (struct UserPrivateKey * sk, struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing){
	/* r and s*/
	element_t r;
	Zr(r,pairing);
	Zr(sk->s,pairing);

	/* sk2 */
	G1(sk->sk2,pairing);
	element_pow_zn(sk->sk2,PK->g,r);

	/* t */
	element_t T;
	Zr(T,pairing);
	element_from_hash(T,sk->sk2,sizeof(sk->sk2));

	/* L */
	element_t L;
	Zr(L,pairing);
	element_t temp_keygen1,temp_keygen2;
	G1(temp_keygen1,pairing);
	G1(temp_keygen2,pairing);
	element_pow_zn(temp_keygen1,PK->g,T);
	element_pow_zn(temp_keygen2,PK->h,sk->s);
	element_mul(temp_keygen1,temp_keygen1,temp_keygen2);
	element_from_hash(L,temp_keygen1,sizeof(temp_keygen1));

	/* sk1_ */
	G1(sk->sk1_,pairing);
	element_pow_zn(temp_keygen1,msk->galpha,L);
	element_pow_zn(temp_keygen2,PK->ga,r);
	element_mul(sk->sk1_,temp_keygen1,temp_keygen2);

	/* sk1i */
	for(int i=0;i<Number_of_attribute;i++){
		G1(sk->sk1i[i],pairing);
		element_pow_zn(sk->sk1i[i],PK->hi[i],r);
	}
 
 	
	puts("KeyGen");

}

void Encryption (struct CipherText * CT,struct PublicKey *PK, pairing_t pairing) {
	/*init vi wi and secret value u about attribute encryption*/
	Zr(CT->u,pairing);
	element_set0(CT->u);
	element_t temp_encryption;
	Zr(temp_encryption,pairing);

	element_t z[Number_of_attribute];
	element_t temp_encryption2,temp_encryption3;
	G1(temp_encryption2,pairing);
	G1(temp_encryption3,pairing);

	for(int i=0;i<Number_of_attribute;i++){

		/* u */
		Zr(CT->wi[i],pairing);
		Zr(CT->vi[i],pairing);
		element_mul(temp_encryption,CT->wi[i],CT->vi[i]);
		element_add(CT->u,CT->u,temp_encryption);

		/* z */
		Zr(z[i],pairing);

		/* Ci */
		G1(CT->Ci[i],pairing);
		element_invert(temp_encryption,z[i]);
		element_pow_zn(temp_encryption3,PK->hi[i],temp_encryption);
		element_pow_zn(temp_encryption2,PK->ga,CT->vi[i]);
		element_mul(CT->Ci[i],temp_encryption2,temp_encryption3);

		/* Di */
		G1(CT->Di[i],pairing);
		element_pow_zn(CT->Di[i],PK->g,z[i]);
	}

	/* M */
	element_t M;
	GT(M,pairing);
	//element_set1(M);

	/* C */
	GT(CT->C,pairing);
	element_pow_zn(CT->C,PK->eggalpha,CT->u);
	element_mul(CT->C,CT->C,M);

	/* C' */
	G1(CT->C_,pairing);
	element_pow_zn(CT->C_,PK->g,CT->u);

 	puts("Encryption");
}

void Decrypt(struct CipherText *CT, struct PublicKey * PK,struct UserPrivateKey * sk, pairing_t pairing){
	/* up */
	element_t up;
	GT(up,pairing);
	element_pairing(up,CT->C_,sk->sk1_);

	/* down */
	element_t down;
	GT(down,pairing);
	element_set1(down);

	element_t temp_down1,temp_down2;
	GT(temp_down1,pairing);
	GT(temp_down2,pairing);

	for(int i=0;i<Number_of_attribute;i++){
		element_pairing(temp_down1,CT->Ci[i],sk->sk2);
		element_pairing(temp_down2,CT->Di[i],sk->sk1i[i]);
		element_mul(temp_down1,temp_down1,temp_down2);
		element_pow_zn(temp_down1,temp_down1,CT->wi[i]);
		element_mul(down,down,temp_down1);

	}

	/* e(g,g)^auL*/
	element_t eggaul;
	GT(eggaul,pairing);
	element_div(eggaul,up,down);

	/* t */
	element_t T;
	Zr(T,pairing);
	element_from_hash(T,sk->sk2,sizeof(sk->sk2));

	/* L */
	element_t L;
	Zr(L,pairing);
	element_t temp_keygen1,temp_keygen2;
	G1(temp_keygen1,pairing);
	G1(temp_keygen2,pairing);
	element_pow_zn(temp_keygen1,PK->g,T);
	element_pow_zn(temp_keygen2,PK->h,sk->s);
	element_mul(temp_keygen1,temp_keygen1,temp_keygen2);
	element_from_hash(L,temp_keygen1,sizeof(temp_keygen1));

	/* M */
	element_t M;
	GT(M,pairing);
	element_t L_invert;
	Zr(L_invert,pairing);
	element_invert(L_invert,L);
	element_pow_zn(eggaul,eggaul,L_invert);
	element_div(M,CT->C,eggaul);


	puts("Decrypt");
//	element_printf("M = %B\n",M);
}


