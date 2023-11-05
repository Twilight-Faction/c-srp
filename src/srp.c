#include "srp.h"
#include "byte_array.h"
#include "bignum_utils.h"
#include "hash_utils.h"

#include <openssl/rand.h>
#include <string.h>
#include <assert.h>

csrp_error_t generate_private_key(group_t const *const group, BIGNUM **const result) {
    csrp_error_t error;

    byte_array_t rand_bytes;

    assert(result != NULL);

    rand_bytes = byte_array_new(group->exponent_strength);

    if (RAND_priv_bytes(rand_bytes.data, (int) rand_bytes.length) <= 0) {
        GOTO_ERROR(CSRP_OPENSSL_FAILURE);
    }

    error = bignum_from_bytes(&rand_bytes, result);

    error:
    byte_array_clear_free(rand_bytes);

    return error;
}

csrp_error_t calculate_public_multiplier(
        group_t const *const group,
        BIGNUM const *const public_key_a,
        BIGNUM const *const public_key_b,
        BIGNUM **const result_u
) {
    byte_array_t bytes_a;
    byte_array_t padded_b;
    byte_array_t result_hash;

    csrp_error_t error;

    int n_bytes_length;
    int result_length;
    int offset;

    assert(group != NULL);
    assert(public_key_a != NULL);
    assert(public_key_b != NULL);
    assert(result_u != NULL);

    n_bytes_length = BN_num_bytes(group->n);
    result_length = 2 * n_bytes_length;

    padded_b = byte_array_new(result_length);
    error = bignum_pad_bytes(public_key_b, group->n, result_length, &padded_b);
    if (!CSRP_IS_ERROR(error)) {
        goto error_1;
    }

    bytes_a = byte_array_new(BN_num_bytes(public_key_a));
    error = bignum_to_bytes(public_key_a, &bytes_a);
    if (!CSRP_IS_ERROR(error)) {
        goto error_2;
    }

    offset = n_bytes_length - (int) bytes_a.length;
    memcpy(padded_b.data + offset, bytes_a.data, bytes_a.length);

    result_hash = byte_array_new(EVP_MAX_MD_SIZE);
    error = apply_hash(EVP_sha256(), &padded_b, 1, &result_hash);
    if (!CSRP_IS_ERROR(error)) {
        goto error_3;
    }

    error = bignum_from_bytes(&result_hash, result_u);
    if (!CSRP_IS_ERROR(error)) {
        goto error_3;
    }

    error_3:
    byte_array_free(result_hash);
    error_2:
    byte_array_free(bytes_a);
    error_1:
    byte_array_free(padded_b);

    return error;
}
