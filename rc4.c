#include <openssl/rc4.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char uchar;

int SSU_SEC_rc4_encrypt(uchar *msg, int msg_len, uchar *sk, int sk_len, uchar **enc_msg, int *enc_msg_len);
int SSU_SEC_rc4_decrypt(uchar *enc_msg, int enc_msg_len, uchar *sk, int sk_len, uchar **msg, int *msg_len);
char* BinaryToBN(uchar *msg, int msg_len);

int main()
{
//    uchar *message = "This is a sample message!!";
    uchar *message = "This is a sample message for testing RC4 stream cipher in OpenSSL.";
   
          //암호키 생성에 필요한 패스워드
    uchar *key = "ThisIsUserPassword";
    uchar *enc_data=NULL;
    int enc_data_len=0, i;
    uchar *dec_data=NULL;
    int dec_data_len=0;

    printf("\nm = %s\n", message);
    printf("m len (bytes) = %d\n", strlen(message)+1);  
    
    SSU_SEC_rc4_encrypt(message, strlen(message)+1, key, strlen(key), &enc_data, &enc_data_len);
    printf("\n** RC4 Encryption OK.\n");
    printf("E(m) = %s\n", BinaryToBN(enc_data, enc_data_len));
    printf("\nE(m) len (bytes)  = %d\n", enc_data_len);

    SSU_SEC_rc4_decrypt(enc_data, enc_data_len, key, strlen(key), &dec_data, &dec_data_len);
    printf("\n** RC4 Decryption OK.\n");
    printf("D(C) = %s\n", dec_data);
    printf("D(C) len (bytes) = %d\n\n", dec_data_len+1);

    free(enc_data);
    free(dec_data);

    return 0;
}



int SSU_SEC_rc4_encrypt(uchar *msg, int msg_len, uchar *sk, int sk_len, uchar **enc_msg, int *enc_msg_len)
{
    RC4_KEY rc4key;

    // RC4 암호키 생성 (No Salt)
    RC4_set_key(&rc4key, sk_len, sk);

    *enc_msg = (uchar*)calloc(msg_len, sizeof(uchar));
    
    RC4(&rc4key, msg_len, msg, *enc_msg);

    // enc_msg에 NULL문자 존재 가능함. 따라서 평문길이로 암호문 길이를 대체함
          // 즉, *enc_msg_len = strlen(*enc_msg);으로 하면 오류 발생함

    *enc_msg_len = msg_len;
//    *enc_msg_len = strlen(*enc_msg);

    return 0;
}


int SSU_SEC_rc4_decrypt(uchar *enc_msg, int enc_msg_len, uchar *sk, int sk_len, uchar **msg, int *msg_len)
{
    RC4_KEY rc4key;

    // RC4 복호키 생성 (No Salt)
    RC4_set_key(&rc4key, sk_len, sk);

    *msg = (uchar*)malloc(enc_msg_len);
    
    RC4(&rc4key, enc_msg_len, enc_msg, *msg);

    *msg_len = strlen(*msg);

    return 0;
}


char* BinaryToBN(uchar *msg, int msg_len)
{
	 BIGNUM *temp;

	 temp = BN_new();
	 BN_init(temp);

	 BN_bin2bn(msg, msg_len, temp); // binary to BN

	 return BN_bn2hex(temp);   // BN to hex
}

