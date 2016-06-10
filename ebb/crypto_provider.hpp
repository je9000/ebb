//
//  crypto_provider.h
//  ebb
//
//  Created by test on 4/17/16.
//  Copyright © 2016 je. All rights reserved.
//

#ifndef crypto_provider_h
#define crypto_provider_h

#include "ebb.hpp"

class ebb_crypto_provider
{
public:
    shared_ebb_derived_key derive_key(std::string, size_t);
    shared_ebb_keyed_data encrypt_block_with_keys(shared_ebb_keyed_data);
    shared_ebb_keyed_data encrypt_block_new_keys(std::string, std::string);
    std::string decrypt_block(shared_ebb_keyed_data);
};

#endif /* crypto_provider_h */
