/**************************************************
 *                                                *
 *      Skudo OÜ HSM - Arduino interface library  *
 *                                                *
 *          Version 1.0 September 2021            *
 *              Copyright Skudo OÜ                *
 *                www.skudo.tech                  *
 **************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "spi_functions.h"
#include "hsm_cli.h"

unsigned char iv[SYMMETRIC_BLOCK_SIZE] = {0};
unsigned char request_buf[48];

// read request won't supply any data, but expect immediate response with data
static int request_read_size(int arguments_size)
{
    int size = sizeof(HsmCommand) + arguments_size;
    request_buf[size] = 0; // extra byte for lag compensation
    return size + 1; // +1 byte for spi report lag compensation
}

// in general request might supply additional data, so can't insert +1 byte for spi lag compensation
static int request_size(int arguments_size)
{
    return sizeof(HsmCommand) + arguments_size;
}

int serialize_poll_request()
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_POLL_READY;
    return request_read_size(4);
}

int serialize_trng_request(int bytes)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_TRNG;
    TrngArguments* trng = (TrngArguments*)(request_buf + sizeof(HsmCommand));
    trng->bytes = bytes;
    return request_read_size(sizeof(TrngArguments));
}

int serialize_key_request(int slot, int private_space, int generate, unsigned char* user_key)
{
    int symmetric_action  = generate ? HSM_KEY_GENERATE_SYMMETRIC : HSM_KEY_SETUP_SYMMETRIC;
    int asymmetric_action = generate ? HSM_KEY_GENERATE_PRIVATE: HSM_KEY_SETUP_PRIVATE;
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_KEY;
    cmd->command = private_space ? asymmetric_action : symmetric_action;

    KeyArguments* key = (KeyArguments*)(request_buf + sizeof(HsmCommand));
    key->slot_idx = slot;
    if(user_key)
        memcpy(key->user_key, user_key, sizeof key->user_key);

    return request_size(sizeof(KeyArguments));
}

int serialize_get_key(int slot, int public)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_KEY_READ;
    cmd->command = public ? HSM_KEY_READ_PUBLIC : HSM_KEY_READ_SYMMETRIC;
    KeyReadArguments* key = (KeyReadArguments*)(request_buf + sizeof(HsmCommand));
    key->slot_idx = slot;
    return request_read_size(sizeof(KeyReadArguments));
}

int serialize_ecdh_setup(int private_idx, int symmetric_idx, unsigned char* public)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_ECDH;
    cmd->command = HSM_SETUP_SECRET;
    ECDHArguments* key = (ECDHArguments*)(request_buf + sizeof(HsmCommand));
    key->private_idx = private_idx;
    key->symmetric_out_idx = symmetric_idx;
    memcpy(key->pub, public, sizeof key->pub);
    return request_size(sizeof(ECDHArguments));
}

int serialize_encryption(int command, int slot_idx, int flags, const unsigned char* iv, unsigned char* data, unsigned data_size)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_ENCRYPTION;
    cmd->command = command;
    EncryptionArguments* cipher = (EncryptionArguments*)(request_buf + sizeof(HsmCommand));
    cipher->slot_idx = slot_idx;
    cipher->flags = flags;
    cipher->data_size = data_size;

    if((flags & HSM_ENCRYPTION_SETUP_IV) && iv)
    {
        memcpy(request_buf + sizeof(HsmCommand) + sizeof(EncryptionArguments), iv, SYMMETRIC_BLOCK_SIZE);
    }
    return request_size(sizeof(EncryptionArguments) + (flags & HSM_ENCRYPTION_SETUP_IV ? SYMMETRIC_BLOCK_SIZE : 0));
}

int serialize_hashing(int init, int finalize, unsigned size)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_HASHING;
    cmd->command = HSM_HASH;
    HashingArguments* h = (HashingArguments*)(request_buf + sizeof(HsmCommand));
    h->data_size = size;
    h->hash_size = init;
    h->flags = (init ? HSM_HASHING_INIT : 0) | (finalize ? HSM_HASHING_FINALIZE : 0);
    return request_size(sizeof(HashingArguments));
}

int serialize_heartbeat(int state)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_MAINTENANCE;
    cmd->command = HSM_HEARTBEAT;
    MaintenanceArguments* h = (MaintenanceArguments*)(request_buf + sizeof(HsmCommand));
    h->command = state;
    return request_size(sizeof(MaintenanceArguments));
}

int serialize_leds(int state)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_MAINTENANCE;
    cmd->command = HSM_LEDS_STATE;
    MaintenanceArguments* h = (MaintenanceArguments*)(request_buf + sizeof(HsmCommand));
    h->command = state;
    return request_size(sizeof(MaintenanceArguments));
}

int serialize_read_blob(int buf_size)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_BLOB_READ;
    cmd->command = 0;
    return request_read_size(0);
}

int serialize_get_string(int code)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_MAINTENANCE;
    cmd->command = code;
    return request_read_size(0);
}

int serialize_erase_key(int _private, int slot)
{
    HsmCommand* cmd = (HsmCommand*)request_buf;
    cmd->category = HSM_KEY;
    cmd->command = _private ? HSM_KEY_ERASE_PRIVATE: HSM_KEY_ERASE_SYMMETRIC;

    KeyArguments* key = (KeyArguments*)(request_buf + sizeof(HsmCommand));
    key->slot_idx = slot;

    return request_size(sizeof(KeyArguments));
}

void read_string(int code, char* buf, size_t buf_len)
{
  int len = serialize_get_string(code);
  send_request(request_buf, len);
  read_reply(buf, buf_len);
}

unsigned char poll_ready()
{
  unsigned char ready;
  int len = serialize_poll_request();
  send_request(request_buf, len);
  read_reply(&ready, sizeof ready);
  return ready;
}

void wait_ready()
{
  while(!poll_ready());
}

void get_random_bytes(unsigned char* buffer, size_t size)
{
  int len = serialize_trng_request(size);

  send_request(request_buf, len);
  read_reply(buffer, size);
}

void erase_key(int slot, int private_space)
{
  int len = serialize_erase_key(private_space, slot);
  complete_request(request_buf, len);
}

void setup_key(int slot, int private_space, int generate, unsigned char* user_key)
{
  int len = serialize_key_request(slot, private_space, generate, user_key);
  complete_request(request_buf, len);
}

void read_key(int slot, int public_space, KeyResponse* key_buf)
{
  int len = serialize_get_key(slot, public_space);
  send_request(request_buf, len);
  read_reply((unsigned char*)key_buf, sizeof(KeyResponse));
}

void setup_ecdh_key(int private_idx, int symmetric_idx, unsigned char* pub)
{
  int len = serialize_ecdh_setup(private_idx, symmetric_idx, pub);
  complete_request(request_buf, len);
}

static void perform_encryption(int command, int slot, int with_cbc, const unsigned char* iv, unsigned char* data, unsigned size)
{
  int flags = with_cbc ? HSM_ENCRYPTION_CBC : 0;

  if(with_cbc && iv)
    flags |= HSM_ENCRYPTION_SETUP_IV;

  int len = serialize_encryption(command, slot, flags, iv, data, size);
  send_request(request_buf, len);
  complete_request(data, size);
}

void encrypt_block(int slot, int with_cbc, const unsigned char* setup_iv, unsigned char* data, unsigned size)
{
    return perform_encryption(HSM_ENCRYPT, slot, with_cbc, setup_iv, data, size);
}

void decrypt_block(int slot, int with_cbc, const unsigned char* setup_iv, unsigned char* data, unsigned size)
{
    return perform_encryption(HSM_DECRYPT, slot, with_cbc, setup_iv, data, size);
}

void hash_block(int init, int finalize, unsigned char* data, unsigned size)
{
  int len = serialize_hashing(init, finalize, size);
  send_request(request_buf, len);
  complete_request(data, size);
}

void set_hearbeat(int status)
{
  int len = serialize_heartbeat(status);
  complete_request(request_buf, len);
}

void user_leds(int status)
{
  int len = serialize_leds(status);
  complete_request(request_buf, len);
}

void read_blob(unsigned char* buf, unsigned buf_size)
{
  int len = serialize_read_blob(buf_size);
  send_request(request_buf, len);
  read_reply(buf, buf_size);
}

int validate_protocol()
{
    unsigned version;
    read_string(HSM_PROTOCOL_VERSION, (char*)&version, sizeof version);
    return version == HSM_CLI_VERSION;
}
