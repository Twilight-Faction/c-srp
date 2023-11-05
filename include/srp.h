#ifndef CSRP_SRP_H
#define CSRP_SRP_H

#include "csrp_error.h"
#include "group.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


csrp_error_t generate_private_key(group_t const *const group, BIGNUM **const result);

csrp_error_t calculate_public_multiplier(
        group_t const *const group,
        BIGNUM const *const public_key_a,
        BIGNUM const *const public_key_b,
        BIGNUM **const result_u
);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_SRP_H */
