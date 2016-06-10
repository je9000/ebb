//
//  ebb.h
//  ebb
//
//  Created by test on 4/17/16.
//  Copyright © 2016 je. All rights reserved.
//

#ifndef ebb_h
#define ebb_h

#include <string>
#include <cstddef>
#include <climits>
#include <memory>

const int PBKDF2_ITER = 655379;
const size_t SALT_SIZE = 64;
const size_t CIPHER_KEY_SIZE = 32;
const size_t MAC_KEY_SIZE = 32;
const size_t IV_SIZE = 16;
const size_t MAC_SIZE = 64;
const size_t CIPHER_BLOCK_SIZE = 16;

typedef uint64_t ebb_blockno_t;

struct ebb_keyed_data {
    std::string key;
    std::string mac_key;
    std::string mac;
    std::string iv;
    std::string data;
    std::string algo;
};
typedef std::shared_ptr<struct ebb_keyed_data> shared_ebb_keyed_data;

struct ebb_keys {
    std::string cipher_key;
    std::string mac_key;
};

struct ebb_block_keys {
    char cipher_key[CIPHER_KEY_SIZE];
    char mac_key[MAC_KEY_SIZE];
} __attribute__((packed));

struct ebb_header {
    uint64_t magic;
    uint64_t version;
    uint64_t algorithm;
    uint64_t difficulty;
} __attribute__((packed));

struct ebb_key_block {
    uint64_t magic;
    uint64_t version;
    uint64_t block_count;
    uint64_t block_size;
    uint64_t algorithms;
    struct ebb_block_keys block_keys[0];
} __attribute__((packed));

struct ebb_data_block {
    char mac[MAC_SIZE];
    char iv[IV_SIZE];
    char data[0];
} __attribute__((packed));

struct ebb_derived_key {
    std::string salt;
    std::string key;
};
typedef std::shared_ptr<struct ebb_derived_key> shared_ebb_derived_key;

std::string ebb_get_random(size_t);
bool hash_compare(std::string, std::string);
ebb_keys split_derived_key(std::string);
size_t calculate_ciphertext_size(size_t);
ebb_blockno_t calculate_block_from_offset(off_t, size_t);

void debug_print_hex(std::string);
void debug_print_keyed_ebb_data(shared_ebb_keyed_data);

#endif /* ebb_h */
