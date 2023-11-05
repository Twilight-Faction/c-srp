#include "srp.h"
#include <openssl/bn.h>

int main() {
    group_t group;
    group_get_8192(&group);

    BIGNUM *result = BN_new();
    generate_private_key(&group, &result);
    BN_print_fp(stdout, result);
    BN_free(result);
    group_free(group);
    return 0;
}
