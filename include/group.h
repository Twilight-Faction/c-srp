#ifndef CSRP_GROUP_H
#define CSRP_GROUP_H

#include "csrp_error.h"
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef struct group {
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *k;

    int32_t exponent_strength;
} group_t;

csrp_error_t
group_create(group_t *const group, char const *prime_n_str, unsigned long generator, int32_t exponent_strength);

csrp_error_t group_get_8192(group_t *const group);

//csrp_error_t group_get_6144(group_t *const group);

static csrp_error_t
calculate_multiplier_k(BIGNUM const *const prime_n, BIGNUM const *const generator, BIGNUM **const result);

void group_free(group_t group);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_GROUP_H */
