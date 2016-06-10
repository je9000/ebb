//
//  openssl.hpp
//  ebb
//
//  Created by test on 4/17/16.
//  Copyright © 2016 je. All rights reserved.
//

#ifndef openssl_hpp
#define openssl_hpp

#include "crypto_provider.hpp"
#include "ebb.hpp"
#include <openssl/hmac.h>

class ebb_crypto_provider_openssl : ebb_crypto_provider
{
public:
    ebb_crypto_provider_openssl();

    shared_ebb_derived_key derive_key(std::string, size_t);
    shared_ebb_keyed_data encrypt_block_with_keys(shared_ebb_keyed_data);
    shared_ebb_keyed_data encrypt_block_new_keys(std::string, std::string);
    std::string decrypt_block(shared_ebb_keyed_data);
private:
    const EVP_CIPHER *ebb_cipher;
    const EVP_MD *ebb_md;
};

class hmac_ctx {
public:
    hmac_ctx();
    ~hmac_ctx();
    hmac_ctx(const hmac_ctx &) = delete;
    hmac_ctx& operator=(const hmac_ctx &) = delete;
    HMAC_CTX ctx;
};

class cipher_ctx {
public:
    cipher_ctx();
    ~cipher_ctx();
    cipher_ctx(const hmac_ctx &) = delete;
    cipher_ctx& operator=(const hmac_ctx &) = delete;
    EVP_CIPHER_CTX ctx;
};

#endif /* openssl_hpp */
