/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in Oct 2016
 * Updated in Jan 2017, update muliple function on GF(2^8).
 *
 */
#include "Common.h"
/*
 * round constants
 */
static uint8_t RC[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
void aes_key_schedule_128(register uint8_t *key, register uint8_t *roundkeys) {

    uint8_t temp[4];
  
   register  uint8_t i,j=0,*last4bytes,*lastround;

    for (i = 0; i < 16; ++i) {
        *roundkeys++ = *key++;
    }

    last4bytes = roundkeys-4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] = SBOX[*last4bytes++];
		for(j=0;j<3;j++)
		{
			temp[j] = SBOX[*last4bytes++];
		}
        j=0;
        temp[0] ^= RC[i];
        lastround = roundkeys-16;
		while(j<4)
		{*roundkeys++ = temp[j] ^ *lastround++;
			j++;
		}
		
      for(j=0;j<12;j++)
	  {
		  *roundkeys++ = *last4bytes++ ^ *lastround++;
		  
	  }      

    }
}
