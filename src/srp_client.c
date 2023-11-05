#include "srp_client.h"
#include <openssl/bn.h>


csrp_error_t calculate_secret(byte_array_t const *const salt, group_t const *const group, char const *const username,
                              char const *const password, bignum_pair_t *const result_secret) {

    BN_CTX *const ctx = BN_CTX_secure_new();

    if (!ctx) {
        secret_clear_free(&result);
        return CSRP_OPENSSL_FAILURE;
    }

    csrp_error_t error = apply_argon2(salt, group, username, password, &result_secret->bignum1);
    if (!CSRP_IS_ERROR(error)) {
        secret_clear_free(&result);
        BN_CTX_free(ctx);

        return error;
    }


    if (!BN_mod_exp_mont_consttime(result.v, group->g, result.x, group->n, ctx, NULL)) {
        secret_clear_free(&result);
        BN_CTX_free(ctx);
        return CSRP_OPENSSL_FAILURE;
    }

    *secret = result;

    return CSRP_OK;
}

void secret_clear_free(bignum_pair_t const *secret) {

}

csrp_error_t calculate_client_public_key(group_t const *const group, bignum_pair_t *const result_keys) {

}


static csrp_error_t apply_argon2(byte_array_t const *const salt, group_t const *const group, char const *const username,
                                 char const *const password, BIGNUM **const result) {

}