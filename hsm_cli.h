/**************************************************
 *                                                *
 *      Skudo OÜ HSM - Arduino interface library  *
 *                                                *
 *          Version 1.0 September 2021            *
 *              Copyright Skudo OÜ                *
 *                www.skudo.tech                  *
 **************************************************/

#pragma once

#include "hsm_protocol.h"

#if defined(__cplusplus)
extern "C" {
#endif

enum {
  SLOT0,
  SLOT1,
  SLOT2,
  SLOT3
};

enum {
  ROOT_PUB = -1
};

enum {
  SYMMETRIC_KEYS,
  KEYPAIRS
};

enum {
  LOAD_USER_KEY,
  GENERATE_RANDOM_KEY
};

int validate_protocol();

unsigned char poll_ready();
void wait_ready();

void get_random_bytes(unsigned char* buffer, size_t size);
void erase_key(int slot, int private_space);
void setup_key(int slot, int private_space, int generate, unsigned char* user_key);
void read_key(int slot, int public_space, KeyResponse* key_buf);
void setup_ecdh_key(int private_idx, int symmetric_idx, unsigned char* pub);
void encrypt_block(int slot, int with_cbc, const unsigned char* setup_iv, unsigned char* data, unsigned size);
void decrypt_block(int slot, int with_cbc, const unsigned char* setup_iv, unsigned char* data, unsigned size);
void hash_block(int init, int finalize, unsigned char* data, unsigned size);
void read_blob(unsigned char* buf, unsigned buf_size);
void read_string(int code, char* buf, size_t buf_len);

// onboard led manipulation
void set_hearbeat(int status);
void user_leds(int status);

#if defined(__cplusplus)
}
#endif
