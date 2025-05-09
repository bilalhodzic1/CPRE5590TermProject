#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

void enclave_print_string(char* str_to_print);
void compute_array_average(int* numbers, size_t cnt);

#if defined(__cplusplus)
}
#endif

#endif
