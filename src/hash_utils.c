#include <assert.h>
#include "hash_utils.h"

csrp_error_t apply_hash(EVP_MD const *const hash_algorithm, byte_array_t const *const inputs, size_t const inputs_count,
                        byte_array_t *const result) {

    EVP_MD_CTX *md_ctx;

    csrp_error_t error = CSRP_OK;

    assert(hash_algorithm != NULL);
    assert(inputs != NULL);
    assert(result != NULL);

    md_ctx = EVP_MD_CTX_new();

    if (!EVP_DigestInit_ex2(md_ctx, hash_algorithm, NULL)) {
        GOTO_ERROR(CSRP_OPENSSL_FAILURE);
    }

    for (size_t i = 0; i < inputs_count; ++i) {
        if (!EVP_DigestUpdate(md_ctx, inputs[i].data, inputs[i].length)) {
            GOTO_ERROR(CSRP_OPENSSL_FAILURE);
        }
    }

    // Unsure of this cast, needs testing
    if (!EVP_DigestFinal_ex(md_ctx, result->data, (unsigned int *) &result->length)) {
        GOTO_ERROR(CSRP_OPENSSL_FAILURE);
    }

    error:
    EVP_MD_CTX_free(md_ctx);

    return error;
}
