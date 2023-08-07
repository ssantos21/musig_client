#pragma once

#ifndef INCLUDE_SECP256K1_ZPK_H
#define INCLUDE_SECP256K1_ZPK_H

extern "C" {
    #include "../secp256k1-zkp/include/secp256k1.h"
    #include "../secp256k1-zkp/include/secp256k1_schnorrsig.h"
    #include "../secp256k1-zkp/include/secp256k1_musig.h"
}

#endif // INCLUDE_SECP256K1_ZPK_H