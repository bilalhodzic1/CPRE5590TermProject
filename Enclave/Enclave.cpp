#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ippcp.h> 

static const int KEY_SIZE = 16;
static const int MSG_LEN = 60;
static const int IV_LEN = 12;
static Ipp8u key128[KEY_SIZE] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                                  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };

static Ipp8u cipherText[MSG_LEN] = { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72,
                                     0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f,
                                     0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
                                     0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
                                     0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3,
                                     0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91 };
static const Ipp8u iv[IV_LEN] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                  0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };

char encrypt_data[BUFSIZ] = "Data to encrypt\n";

void decrypt_object(Ipp8u *pOutPlainText, Ipp8u *unsealedkey128){
    int AESGCMSize = 0;
    IppsAES_GCMState* pAESGCMState = 0;
    ippsAES_GCMGetSize(&AESGCMSize);
    pAESGCMState = (IppsAES_GCMState*)(new Ipp8u[AESGCMSize]);
    ippsAES_GCMInit(unsealedkey128, KEY_SIZE, pAESGCMState, AESGCMSize);
    ippsAES_GCMStart(iv, IV_LEN, NULL, 0, pAESGCMState);
    ippsAES_GCMDecrypt(cipherText, pOutPlainText, MSG_LEN, pAESGCMState);
    ippsAES_GCMReset(pAESGCMState);
    if (pAESGCMState)
        delete[] (Ipp8u*)pAESGCMState;
}

void get_key(const uint8_t *sealed_blob, Ipp8u *unsealedkey128){
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, NULL, 0, decrypt_data, &decrypt_data_len);
    memcpy(unsealedkey128, decrypt_data, KEY_SIZE);
}

sgx_status_t test_aes_key(const uint8_t *sealed_blob, size_t data_size){
    Ipp8u unsealedkey128[KEY_SIZE];
    get_key(sealed_blob, unsealedkey128);
    Ipp8u pOutPlainText[MSG_LEN] = {};
    decrypt_object(pOutPlainText, unsealedkey128);
    print_byte_by_byte((const char*)pOutPlainText, MSG_LEN);
}

sgx_status_t seal_aes_key(uint8_t* sealed_blob, uint32_t data_size){
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, sizeof(key128));
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    sgx_status_t  err = sgx_seal_data(0, NULL, sizeof(key128), (uint8_t *)key128, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

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
    return sgx_calc_sealed_data_size(0, sizeof(key128));
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