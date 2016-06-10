//
//  openssl.cpp
//  ebb
//
//  Created by test on 4/17/16.
//  Copyright © 2016 je. All rights reserved.
//

#include "ebb.hpp"
#include "openssl.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

hmac_ctx::hmac_ctx() {
    HMAC_CTX_init(&this->ctx);
}

hmac_ctx::~hmac_ctx() {
    HMAC_CTX_cleanup(&this->ctx);
}

cipher_ctx::cipher_ctx() {
    EVP_CIPHER_CTX_init(&this->ctx);
}

cipher_ctx::~cipher_ctx() {
    EVP_CIPHER_CTX_cleanup(&this->ctx);
}

std::string hmac_data(std::string key, std::string iv, std::string data)
{
    unsigned char computed_hash[EVP_MAX_MD_SIZE];
    int r;
    unsigned int computed_len;
    hmac_ctx ctx;

    if (key.length() > INT_MAX) throw std::runtime_error("key is too large");
    if (data.length() > INT_MAX) throw std::runtime_error("data is too large");
    if (iv.length() > INT_MAX) throw std::runtime_error("iv is too large");

    r = HMAC_Init_ex(&ctx.ctx,
                     reinterpret_cast<const void *>(key.c_str()),
                     static_cast<int>(key.length()),
                     EVP_sha512(),
                     NULL
                     );
    if (r == 0) throw std::runtime_error("HMAC_Init_ex");

    r = HMAC_Update(&ctx.ctx,
                    reinterpret_cast<const unsigned char *>(iv.c_str()),
                    static_cast<int>(iv.length())
                    );
    if (r == 0) throw std::runtime_error("HMAC_Update");

    r = HMAC_Update(&ctx.ctx,
                    reinterpret_cast<const unsigned char *>(data.c_str()),
                    static_cast<int>(data.length())
                    );
    if (r == 0) throw std::runtime_error("HMAC_Update");

    r = HMAC_Final(&ctx.ctx, computed_hash, &computed_len);
    if (r == 0) throw std::runtime_error("HMAC_Final");

    return std::string(reinterpret_cast<const char *>(computed_hash), computed_len);
}

ebb_crypto_provider_openssl::ebb_crypto_provider_openssl() : ebb_cipher(EVP_aes_256_cbc()), ebb_md(EVP_sha512())
{
    if (EVP_CIPHER_block_size(ebb_cipher) != CIPHER_BLOCK_SIZE) throw std::length_error("Compiled cipher block size mismatch");
    if (EVP_CIPHER_iv_length(ebb_cipher) != IV_SIZE) throw std::length_error("Compiled cipher iv size mismatch");
    if (EVP_CIPHER_key_length(ebb_cipher) != CIPHER_KEY_SIZE) throw std::length_error("Compiled cipher key size mismatch");
    if (EVP_MD_size(ebb_md) != MAC_SIZE) throw std::length_error("Compiled mac size mismatch");
}

shared_ebb_derived_key ebb_crypto_provider_openssl::derive_key(std::string password, size_t size) {
    std::string salt = ebb_get_random(SALT_SIZE);
    std::unique_ptr<unsigned char[]> outbuf(new unsigned char[size]);
    shared_ebb_derived_key derived = std::make_shared<struct ebb_derived_key>();
    int r;

    if (size > INT_MAX) throw std::runtime_error("size is too large");

    r = PKCS5_PBKDF2_HMAC(
                      password.c_str(),
                      static_cast<int>(password.length()),
                      reinterpret_cast<const unsigned char *>(salt.c_str()),
                      static_cast<int>(salt.size()),
                      PBKDF2_ITER,
                      EVP_sha512(),
                      static_cast<int>(size),
                      outbuf.get()
    );
    if (r == 0) throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");

    derived->key = std::string(reinterpret_cast<char *>(outbuf.get()), size);
    derived->salt = salt;
    return derived;
}

shared_ebb_keyed_data ebb_crypto_provider_openssl::encrypt_block_with_keys(shared_ebb_keyed_data keyed_data)
{
    auto encrypted = std::make_shared<struct ebb_keyed_data>();
    int r, encrypted_size, final_encrypted_size;
    size_t outbuf_len;
    std::string computed_hash;
    cipher_ctx ctx;
    std::unique_ptr<unsigned char[]> outbuf;

    if (keyed_data->data.length() > INT_MAX) throw std::runtime_error("key is too large");

    if (keyed_data->data.length() % EVP_CIPHER_block_size(EVP_aes_256_cbc()) != 0) {
        throw std::runtime_error("Data length not a multiple of cipher block size");
    }

    outbuf_len = keyed_data->data.length();
    outbuf = std::unique_ptr<unsigned char []>(new unsigned char[outbuf_len]);

    r = EVP_EncryptInit_ex(&ctx.ctx,
                           EVP_aes_256_cbc(),
                           NULL,
                           reinterpret_cast<const unsigned char *>(keyed_data->key.c_str()),
                           reinterpret_cast<const unsigned char *>(keyed_data->iv.c_str())
                           );
    if (r == 0) throw std::runtime_error("EVP_DecryptInit_ex");

    // Don't pad, we only encrypt full blocks.
    EVP_CIPHER_CTX_set_padding(&ctx.ctx, 0);

    r = EVP_EncryptUpdate(&ctx.ctx,
                          outbuf.get(),
                          &encrypted_size,
                          reinterpret_cast<const unsigned char *>(keyed_data->data.c_str()),
                          static_cast<int>(keyed_data->data.length())
                          );
    if (r == 0) throw std::runtime_error("EVP_DecryptUpdate");

    r = EVP_EncryptFinal_ex(&ctx.ctx,
                            outbuf.get() + encrypted_size,
                            &final_encrypted_size
                            );
    if (r == 0) throw std::runtime_error("EVP_DecryptUpdate");

    if (encrypted_size + final_encrypted_size != keyed_data->data.length())
    {
        throw std::runtime_error("Didn't encrypt the correct number of blocks.");
    }


    encrypted->data = std::string(reinterpret_cast<char *>(outbuf.get()), outbuf_len);
    encrypted->algo = keyed_data->algo;
    encrypted->mac_key = keyed_data->mac_key;
    encrypted->iv = keyed_data->iv;
    encrypted->key = keyed_data->key;

    computed_hash = hmac_data(keyed_data->mac_key, keyed_data->iv, encrypted->data);
    encrypted->mac = computed_hash;

    debug_print_keyed_ebb_data(encrypted);
    
    return encrypted;
}

shared_ebb_keyed_data ebb_crypto_provider_openssl::encrypt_block_new_keys(std::string algo, std::string data)
{
    auto encrypted = std::make_shared<struct ebb_keyed_data>();

    encrypted->algo = algo;
    encrypted->data = data;
    encrypted->iv = ebb_get_random(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    encrypted->mac_key = ebb_get_random(EVP_CIPHER_key_length(EVP_aes_256_cbc()));
    encrypted->key = ebb_get_random(EVP_CIPHER_key_length(EVP_aes_256_cbc()));
    return encrypt_block_with_keys(encrypted);
}

std::string ebb_crypto_provider_openssl::decrypt_block(shared_ebb_keyed_data keyed_data)
{
    int r, decrypted_size, final_decrypted_size;
    size_t outbuf_len;
    std::string computed_hash;
    cipher_ctx ctx;
    std::unique_ptr<unsigned char[]> outbuf;

    debug_print_keyed_ebb_data(keyed_data);

    if (keyed_data->data.length() > INT_MAX) throw std::runtime_error("key is too large");

    if (keyed_data->key.length() != EVP_CIPHER_key_length(EVP_aes_256_cbc())) {
        throw std::runtime_error("Key too small");
    }

    if (keyed_data->iv.length() != EVP_CIPHER_iv_length(EVP_aes_256_cbc())) {
        throw std::runtime_error("IV too small");
    }

    if (keyed_data->data.length() % EVP_CIPHER_block_size(EVP_aes_256_cbc()) != 0) {
        throw std::runtime_error("Data length not a multiple of cipher block size");
    }

    outbuf_len = keyed_data->data.length();
    outbuf = std::unique_ptr<unsigned char []>(new unsigned char[outbuf_len]);

    computed_hash = hmac_data(keyed_data->mac_key, keyed_data->iv, keyed_data->data);
    if (!hash_compare(computed_hash, keyed_data->mac)) {
        throw std::runtime_error("HMAC failed");
    }

    r = EVP_DecryptInit_ex(&ctx.ctx,
                       EVP_aes_256_cbc(),
                       NULL,
                       reinterpret_cast<const unsigned char *>(keyed_data->key.c_str()),
                       reinterpret_cast<const unsigned char *>(keyed_data->iv.c_str())
    );
    if (r == 0) throw std::runtime_error("EVP_DecryptInit_ex");

    // Don't pad, we only encrypt full blocks.
    EVP_CIPHER_CTX_set_padding(&ctx.ctx, 0);

    r = EVP_DecryptUpdate(&ctx.ctx,
                          outbuf.get(),
                          &decrypted_size,
                          reinterpret_cast<const unsigned char *>(keyed_data->data.c_str()),
                          static_cast<int>(keyed_data->data.length())
    );
    if (r == 0) throw std::runtime_error("EVP_DecryptUpdate");

    r = EVP_DecryptFinal_ex(&ctx.ctx,
                          outbuf.get() + decrypted_size,
                          &final_decrypted_size
    );
    if (r == 0) throw std::runtime_error("EVP_DecryptUpdate");

    if (decrypted_size + final_decrypted_size != keyed_data->data.length())
    {
        throw std::runtime_error("Didn't decrypt the correct number of blocks.");
    }

    return std::string(reinterpret_cast<char *>(outbuf.get()), outbuf_len);
}