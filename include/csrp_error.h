#ifndef CSRP_CSRP_ERROR_H
#define CSRP_CSRP_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef enum csrp_error {
    CSRP_OK = 0,
    CSRP_NULL_POINTER,
    CSRP_OPENSSL_FAILURE,
} csrp_error_t;

#define CSRP_IS_ERROR(csrp_error) ((csrp_error) != CSRP_OK)

#define GOTO_ERROR(csrp_error) \
    error = csrp_error;        \
    goto error


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CSRP_CSRP_ERROR_H */
