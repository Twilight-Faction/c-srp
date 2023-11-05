#ifndef CSRP_SRP_CLIENT_H
#define CSRP_SRP_CLIENT_H

#include "csrp_error.h"
#include "group.h"
#include "byte_array.h"
#include "bignum_pair.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */




csrp_error_t calculate_secret(byte_array_t const *const salt, group_t const *const group, char const *const username,
                              char const *const password, bignum_pair_t *const result_secret);

void secret_clear_free(bignum_pair_t const *secret);

csrp_error_t calculate_client_public_key(group_t const *const group, bignum_pair_t *const result_keys);

//csrp_error_t calculate_client_master_key(
//        secret_t const *secret,
//        group_t const *group,
//        BIGNUM const *A,
//        BIGNUM const *B,
//        BIGNUM const *a
//);

static csrp_error_t apply_argon2(byte_array_t const *const salt, group_t const *const group, char const *const username,
                                 char const *const password, BIGNUM **const result);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_SRP_CLIENT_H */
