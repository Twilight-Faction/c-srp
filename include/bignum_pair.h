#ifndef CSRP_BIGNUM_PAIR_H
#define CSRP_BIGNUM_PAIR_H

#include <openssl/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef struct bignum_pair {
    BIGNUM *bignum1;
    BIGNUM *bignum2;
} bignum_pair_t;


bignum_pair_t bignum_pair_new(size_t length);

bignum_pair_t bignum_pair_secure_new(size_t length);

void bignum_pair_free(bignum_pair_t pair);

void bignum_pair_clear_free(bignum_pair_t pair);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* CSRP_BIGNUM_PAIR_H */
