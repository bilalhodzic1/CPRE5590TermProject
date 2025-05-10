#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>
#include "sgx_trts.h"
#include "sgx_tseal.h"
#if defined(__cplusplus)
extern "C" {
#endif

void enclave_print_string(char* str_to_print);
void compute_array_average(int* numbers, size_t cnt);
sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size);
uint32_t get_sealed_data_size();
sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size);
#if defined(__cplusplus)
}
#endif

#endif
