#include <malloc.h>
#include <string.h>

#include "byte_array.h"

byte_array_t byte_array_new(size_t length) {
    byte_array_t temp;

    temp.data = malloc(sizeof(byte_t) * length);
    temp.length = length;

    return temp;
}


void byte_array_free(byte_array_t b_arr) {
    free(b_arr.data);
}

void byte_array_clear_free(byte_array_t b_arr) {
    if (b_arr.data) {
        memset(b_arr.data, 0, sizeof(*b_arr.data) * b_arr.length);
    }

    free(b_arr.data);
}
