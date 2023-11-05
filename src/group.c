#include "group.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <assert.h>

#include "bignum_utils.h"
#include "hash_utils.h"

csrp_error_t group_create(group_t *const group, char const *prime_n_str, unsigned long generator,
                          int32_t exponent_strength) {

    BIGNUM *prime_n_bignum;
    BIGNUM *generator_bignum;
    BIGNUM *multiplier_k_bignum;

    csrp_error_t error;

    assert(group != NULL);

    prime_n_bignum = BN_new();
    error = bignum_from_string(prime_n_str, &prime_n_bignum);

    if (CSRP_IS_ERROR(error)) {
        return error;
    }

    generator_bignum = BN_new();
    BN_set_word(generator_bignum, generator);

    multiplier_k_bignum = BN_new();
    error = calculate_multiplier_k(prime_n_bignum, generator_bignum, &multiplier_k_bignum);

    if (CSRP_IS_ERROR(error)) {
        return error;
    }

    group->n = prime_n_bignum;
    group->g = generator_bignum;
    group->k = multiplier_k_bignum;
    group->exponent_strength = exponent_strength;

    return CSRP_OK;
}

csrp_error_t group_get_8192(group_t *const group) {
    char const *prime_n_str;

    csrp_error_t error;

    prime_n_str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                  "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                  "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                  "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                  "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
                  "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
                  "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
                  "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
                  "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
                  "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
                  "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
                  "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
                  "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
                  "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
                  "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
                  "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
                  "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
                  "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
                  "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
                  "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
                  "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
                  "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
                  "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
                  "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
                  "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
                  "6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA"
                  "3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C"
                  "5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
                  "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886"
                  "2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6"
                  "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5"
                  "0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268"
                  "359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6"
                  "FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
                  "60C980DD98EDD3DFFFFFFFFFFFFFFFFF";

    error = group_create(group, prime_n_str, 19, 624 / 8);
    if (CSRP_IS_ERROR(error)) {
        return error;
    }

    return CSRP_OK;
}

//csrp_error_t get_6144_group(group_t *const group) {
//
//}

static csrp_error_t
calculate_multiplier_k(BIGNUM const *const prime_n, BIGNUM const *const generator, BIGNUM **const result) {
#define INPUT_COUNT 2

    csrp_error_t error;
    byte_array_t result_hash;
    byte_array_t inputs[INPUT_COUNT] = {
            byte_array_new(BN_num_bytes(prime_n)),
            byte_array_new(BN_num_bytes(prime_n))
    };

    assert(prime_n != NULL);
    assert(generator != NULL);
    assert(result != NULL);

    error = bignum_pad_bytes(generator, prime_n, BN_num_bytes(prime_n), &inputs[0]);
    if (CSRP_IS_ERROR(error)) {
        goto error_1;
    }

    error = bignum_to_bytes(prime_n, &inputs[1]);
    if (CSRP_IS_ERROR(error)) {
        goto error_2;
    }

    result_hash = byte_array_new(EVP_MAX_MD_SIZE);
    error = apply_hash(EVP_sha256(), inputs, INPUT_COUNT, &result_hash);
    if (CSRP_IS_ERROR(error)) {
        goto error_3;
    }

    error = bignum_from_bytes(&result_hash, result);
    if (CSRP_IS_ERROR(error)) {
        goto error_3;
    }

    error_3:
    byte_array_free(result_hash);
    error_2:
    byte_array_free(inputs[1]);
    error_1:
    byte_array_free(inputs[0]);

    return error;
#undef INPUT_COUNT
}

void group_free(group_t group) {
    BN_free(group.n);
    BN_free(group.g);
    BN_free(group.k);
}
