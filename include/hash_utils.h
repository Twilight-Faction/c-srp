#ifndef CSRP_HASH_UTILS_H
#define CSRP_HASH_UTILS_H

#include "byte_array.h"
#include "csrp_error.h"

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


csrp_error_t apply_hash(EVP_MD const *const hash_algorithm, byte_array_t const *const inputs, size_t const inputs_count,
                        byte_array_t *const result);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_HASH_UTILS_H */
