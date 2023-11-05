#ifndef CSRP_BIGNUM_UTILS_H
#define CSRP_BIGNUM_UTILS_H

#include <openssl/types.h>

#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


csrp_error_t bignum_from_string(char const *const from_str, BIGNUM **const to_bignum);

csrp_error_t bignum_from_bytes(byte_array_t const *const from_bytes, BIGNUM **const to_bignum);

csrp_error_t bignum_pad_bytes(BIGNUM const *const bignum, BIGNUM const *const modulus, int const pad_to,
                              byte_array_t *const result);

csrp_error_t bignum_to_bytes(BIGNUM const *const bignum, byte_array_t *const result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_BIGNUM_UTILS_H */
