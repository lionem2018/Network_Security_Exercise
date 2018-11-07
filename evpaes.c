#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SK_SIZE 128

typedef unsigned char uchar;
uchar IVseedConstant[AES_BLOCK_SIZE] = "ItIsIVseedValue";

int SSU_SEC_sk_gen(uchar **sk, int *sk_len);
int SSU_SEC_evp_aes_encrypt(uchar *msg, int msg_len, uchar *sk, const EVP_CIPHER* cipher, uchar **enc, int *enc_len);
int SSU_SEC_evp_aes_decrypt(uchar *enc, int enc_len, uchar *sk, const EVP_CIPHER* cipher, uchar **dec, int *dec_len);
char* BinaryToBN(uchar *msg, int msg_len);
void printUsage();

int main(int argc, char* argv[]){
        uchar *msg = "This is a sample message!!";
//	uchar *msg = "This is the sample message for testing AES cipher with EVP(Envelope) API in OpenSSL.";
	uchar *enc, *dec, *sk;
	int enc_len, dec_len, sk_len;
	const EVP_CIPHER* cipher;

	if(argc < 2){
	   	printUsage();
	   	return -1;
	}

	switch(atoi(argv[1])){
   		case 1: 
			printf("\n********** ECB MODE **********\n\n"); 
			cipher = EVP_aes_128_ecb();
			break;
     		case 2: 
     			printf("\n********** CBC MODE **********\n\n"); 
     			cipher = EVP_aes_128_cbc();
     			break;
      		case 3: 
      			printf("\n********** CFB MODE **********\n\n"); 
      			cipher = EVP_aes_128_cfb();
      			break;
      		case 4: 
      			printf("\n********** OFB MODE **********\n\n"); 
      			cipher = EVP_aes_128_ofb();
      			break;
      		case 5:
      			printf("\n********** CTR MODE **********\n\n"); 
      			cipher = EVP_aes_128_ctr();
      			break;
	      	default:
			printUsage();
	      	return -1;
	}

	if(SSU_SEC_sk_gen(&sk, &sk_len)){
        	printf("AES Key generation OK. \n");
    		printf("AES Key = %s\n", BinaryToBN(sk, sk_len));
    		printf("AES Key len (bytes)  = %d\n", sk_len);
    	}
    	else{
    		printf("AES Key generation Fail.\n");
    		return -1;
    	}

	printf("\nm = %s\n", msg);
    	printf("m len (bytes) = %d\n", strlen(msg)+1);

    	SSU_SEC_evp_aes_encrypt(msg, strlen(msg)+1, sk, cipher, &enc, &enc_len);
    	printf("\n** EVP_AES Encryption OK.\n");
    	printf("E(m) = %s\n", BinaryToBN(enc, enc_len));
    	printf("E(m) len (bytes)  = %d\n", enc_len);

    	SSU_SEC_evp_aes_decrypt(enc, enc_len, sk, cipher, &dec, &dec_len);
    	printf("\n** EVP_AES Decryption OK.\n");
    	printf("D(C) = %s\n", dec);
    	printf("D(C) len (bytes) = %d\n\n", dec_len);

    	free(enc);
    	free(dec);

    	return 0;
}

int SSU_SEC_sk_gen(uchar **sk, int *sk_len)
{
    BIGNUM *rnd=BN_new();
    int ret;
    char *seed_msg = "message for seed";
    RAND_seed(seed_msg, strlen(seed_msg));                 // random seed
    ret = BN_rand(rnd, SK_SIZE, 1, 0);
    *sk_len = BN_num_bytes(rnd);
    *sk = malloc(*sk_len);
    BN_bn2bin(rnd, *sk);

    return ret;
}

int SSU_SEC_evp_aes_encrypt(uchar *msg, int msg_len, uchar *sk, const EVP_CIPHER* cipher, uchar **enc, int *enc_len){
	EVP_CIPHER_CTX ctx;
	int ret = 1, tmplen;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, sk, IVseedConstant);

    	*enc = malloc(msg_len + AES_BLOCK_SIZE);

	if(!EVP_EncryptUpdate(&ctx, *enc, enc_len, msg, msg_len))
		ret = 0;

	if(!EVP_EncryptFinal_ex(&ctx, *enc+(*enc_len), &tmplen))
        ret = 0;
    
    	*enc_len += tmplen;
    
    	EVP_CIPHER_CTX_cleanup(&ctx);

    	return ret;
}

int SSU_SEC_evp_aes_decrypt(uchar *enc, int enc_len, uchar *sk, const EVP_CIPHER* cipher, uchar **dec, int *dec_len){
	EVP_CIPHER_CTX ctx;
	int ret = 1, tmplen;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, sk, IVseedConstant);

	*dec = malloc(enc_len);

	if(!EVP_DecryptUpdate(&ctx, *dec, dec_len, enc, enc_len))
		ret = 0;

	if(!EVP_DecryptFinal_ex(&ctx, *dec+(*dec_len), &tmplen))
        ret = 0;
    
    	*dec_len += tmplen;
    
    	EVP_CIPHER_CTX_cleanup(&ctx);

    	return ret;
}	

char* BinaryToBN(uchar *msg, int msg_len)
{
     BIGNUM *temp;

     temp = BN_new();
     BN_init(temp);

     BN_bin2bn(msg, msg_len, temp); // binary to BN

     return BN_bn2hex(temp);   // BN to hex
}

void printUsage(){
	printf("Usage : ./evpaes <mode> (1:ECB, 2:CBC, 3:CFB, 4:OFB, 5:CTR)\n");
}
