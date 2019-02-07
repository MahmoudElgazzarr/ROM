/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in May 2016
 *
 */



//#include <avr/io.h>

#include "Common.h"


int main(int argc, char *argv[]) {

	

	/* 128 bit key */
	static uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,

	};

	static uint8_t plaintext[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};

	uint8_t ciphertext[AES_BLOCK_SIZE];
	
	
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];
	// key schedule
	aes_key_schedule_128(key, roundkeys);
	// encryption
	aes_encrypt_128(roundkeys, plaintext, ciphertext);

	// decryption
	aes_decrypt_128(roundkeys, ciphertext,ciphertext);

	return 0;
}