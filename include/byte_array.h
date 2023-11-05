#ifndef CSRP_BYTE_ARRAY_H
#define CSRP_BYTE_ARRAY_H

#include <stdint.h>
#include <stddef.h>

#include "csrp_error.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef uint8_t byte_t;

typedef struct byte_array {
    byte_t *data;
    size_t length;
} byte_array_t;

byte_array_t byte_array_new(size_t length);

void byte_array_free(byte_array_t b_arr);

void byte_array_clear_free(byte_array_t b_arr);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_BYTE_ARRAY_H */
