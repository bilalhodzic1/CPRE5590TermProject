#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

char encrypt_data[BUFSIZ] = "Data to encrypt\n";

void enclave_print_string(char* str_to_print){
    ocall_print_string(str_to_print);
}

void compute_array_average(int* numbers, size_t cnt){
    int array_size = (int)cnt;
    int i;
    double sum = 0;
    for(i = 0; i < array_size; i++){
        sum += numbers[i];
    }
    double average = sum / (double) array_size;
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "Avg: %.2lf\n", average);
    ocall_print_string(buffer);
}

uint32_t get_sealed_data_size()
{
    return sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
}

sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    sgx_status_t  err = sgx_seal_data(0, NULL, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, NULL, 0, decrypt_data, &decrypt_data_len);
    ocall_print_string((char*)decrypt_data);
    free(decrypt_data);
    return ret;
}