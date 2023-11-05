#include "bignum_utils.h"
#include <openssl/bn.h>
#include <assert.h>

csrp_error_t bignum_from_string(char const *const from_str, BIGNUM **const to_bignum) {
    assert(from_str != NULL);
    assert(to_bignum != NULL);
    assert(*to_bignum != NULL);

    if (BN_hex2bn(to_bignum, from_str) == 0) {
        return CSRP_OPENSSL_FAILURE;
    }

    return CSRP_OK;
}

csrp_error_t bignum_from_bytes(byte_array_t const *const from_bytes, BIGNUM **const to_bignum) {
    assert(from_bytes != NULL);
    assert(to_bignum != NULL);
    assert(*to_bignum != NULL);

    if (!BN_bin2bn(from_bytes->data, (int) from_bytes->length, *to_bignum)) {
        return CSRP_OPENSSL_FAILURE;
    }

    return CSRP_OK;
}

csrp_error_t bignum_pad_bytes(BIGNUM const *const bignum, BIGNUM const *const modulus, int const pad_to,
                              byte_array_t *const result) {
    csrp_error_t error = CSRP_OK;

    BIGNUM *x_mod_n;
    BN_CTX *ctx;

    assert(bignum != NULL);
    assert(result != NULL);
    assert(result->data != NULL);

    x_mod_n = BN_new();
    ctx = BN_CTX_new();

    if (!BN_mod(x_mod_n, bignum, modulus, ctx)) {
        error = CSRP_OPENSSL_FAILURE;
        goto error;
    }

    if (BN_bn2binpad(x_mod_n, result->data, pad_to) != pad_to) {
        error = CSRP_OPENSSL_FAILURE;
    }

    error:
    BN_free(x_mod_n);

    return error;
}


csrp_error_t bignum_to_bytes(BIGNUM const *const bignum, byte_array_t *const result) {
    int expected_bytes;
    
    assert(bignum != NULL);
    assert(result != NULL);
    assert(result->data != NULL);

    expected_bytes = BN_num_bytes(bignum);

    if (BN_bn2bin(bignum, result->data) != expected_bytes) {
        return CSRP_OPENSSL_FAILURE;
    }

    return CSRP_OK;
}
