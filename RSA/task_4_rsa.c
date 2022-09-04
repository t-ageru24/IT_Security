#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
	        char * number_str = BN_bn2hex(a);
		        printf("%s %s\n", msg, number_str);
			        OPENSSL_free(number_str);
}

int main ()
{
	        BN_CTX *ctx = BN_CTX_new();
		BIGNUM *n = BN_new();
		BIGNUM *M = BN_new();
		BIGNUM *M2 = BN_new();
		BIGNUM *d = BN_new();
		BIGNUM *sign = BN_new();
		BIGNUM *sign_M2 = BN_new();

		BN_hex2bn(&M, "49206F776520796F752024323030302E");
		BN_hex2bn(&M2, "49206F776520796F752024333030302E");
		BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
		BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

		printf("\n\n");

		BN_mod_exp(sign, M, d, n, ctx);
		printBN("M^d mod n = ", sign);

		BN_mod_exp(sign_M2, M2, d, n, ctx);																	printBN("M2^d mod n = ", sign_M2);
		return 0;
}