//
//  ebb.cpp
//  ebb
//
//  Created by test on 4/17/16.
//  Copyright © 2016 je. All rights reserved.
//

#include "ebb.hpp"
#include <iostream>
#include <fstream>

std::string ebb_get_random(size_t size)
{
    std::unique_ptr<char[]> random(new char[size]);
    std::ifstream urand;

    urand.open("/dev/urandom", std::ifstream::in);
    urand.read(random.get(), size);

    return std::string(std::move(random.get()), size);
}

bool hash_compare(std::string s1, std::string s2)
{
    char diff = 0;
    if (s1.length() != s2.length()) return false;

    for (size_t x = 0; x < s1.length(); x++) {
        diff |= s1[x] ^ s2[x];
    }
    return diff == 0;
}

ebb_keys split_derived_key(std::string derived_key)
{
    ebb_keys keys;

    if (derived_key.length() < CIPHER_KEY_SIZE + MAC_KEY_SIZE) throw std::runtime_error("derived key is too short");

    keys.cipher_key = derived_key.substr(0, CIPHER_KEY_SIZE);
    keys.mac_key = derived_key.substr(CIPHER_KEY_SIZE, MAC_KEY_SIZE);

    return keys;
}

size_t calculate_ciphertext_size(size_t disk_block_size)
{
    size_t ciphertext_size = disk_block_size - sizeof(struct ebb_data_block);

    ciphertext_size -= ciphertext_size % CIPHER_BLOCK_SIZE;

    return ciphertext_size;
}

ebb_blockno_t calculate_block_from_offset(off_t offset, size_t ciphertext_size)
{
    return offset / ciphertext_size;
}

void debug_print_hex(std::string s)
{
    std::ios_base::fmtflags flags = std::cerr.flags();
    std::streamsize pre = std::cerr.precision();
    char fill  = std::cerr.fill();

    for (int x = 0; x < s.length(); x++) std::cerr << std::hex << +(u_char(s[x]));
    std::cerr << std::endl;

    std::cerr.flags(flags);
    std::cerr.precision(pre);
    std::cerr.fill(fill);
}

void debug_print_keyed_ebb_data(shared_ebb_keyed_data keyed_data)
{
    std::cerr << std::endl << "debug_print_keyed_ebb_data: " << std::endl;
    std::cerr << " key = " << keyed_data->key.length() << " = ";
    debug_print_hex(keyed_data->key);
    std::cerr << " iv = " << keyed_data->iv.length() << " = ";
    debug_print_hex(keyed_data->iv);
    std::cerr << " mac_key = " << keyed_data->mac_key.length() << " = ";
    debug_print_hex(keyed_data->mac_key);
    std::cerr << " mac = " << keyed_data->mac.length() << " = ";
    debug_print_hex(keyed_data->mac);
    std::cerr << " data = " << keyed_data->data.length() << " = ";
    debug_print_hex(keyed_data->data);
}