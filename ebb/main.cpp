//
//  main.cpp
//  ebb
//
//  Created by test on 4/17/16.
//  Copyright © 2016 je. All rights reserved.
//

#include <iostream>
#include "ebb.hpp"
#include "crypto_provider.hpp"
#include "crypto_provider/openssl.hpp"

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";

    ebb_crypto_provider_openssl crypto;

    std::string data = "hello butts1234\n";

    auto a = crypto.encrypt_block_new_keys("algo", data);
    auto b = crypto.decrypt_block(a);

    std::cout << b;

    return 0;
}
