#include "Enclave.h"

#include <ippcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "Enclave_t.h"

static const int KEY_SIZE = 16;
static const int MSG_LEN = 30;
static const int IV_LEN = 12;
static Ipp8u key128_blank[KEY_SIZE] = {};

char encrypt_data[BUFSIZ] = "Data to encrypt\n";

void decrypt_object(Ipp8u *pOutPlainText, Ipp8u *unsealedkey128, Ipp8u *inputData, int totalLen) {
    const Ipp8u *iv = inputData;                   // First 12 bytes
    const Ipp8u *tag = inputData + totalLen - 16;  // Last 16 bytes
    const Ipp8u *cipherText = inputData + IV_LEN;  // After IV
    int MSG_LEN = totalLen - IV_LEN - 16;          // Ciphertext length

    int AESGCMSize = 0;
    IppsAES_GCMState *pAESGCMState = 0;
    ippsAES_GCMGetSize(&AESGCMSize);
    pAESGCMState = (IppsAES_GCMState *)(new Ipp8u[AESGCMSize]);

    ippsAES_GCMInit(unsealedkey128, KEY_SIZE, pAESGCMState, AESGCMSize);
    ippsAES_GCMStart(iv, IV_LEN, NULL, 0, pAESGCMState);
    ippsAES_GCMDecrypt(cipherText, pOutPlainText, MSG_LEN, pAESGCMState);

    Ipp8u computedTag[16];
    ippsAES_GCMGetTag(computedTag, 16, pAESGCMState);
    bool tagMatches = memcmp(computedTag, tag, 16) == 0;
    if (!tagMatches) {
        char buffer[] = "Failed tag check";
        ocall_print_string(buffer);
    }
    ippsAES_GCMReset(pAESGCMState);
    if (pAESGCMState) delete[] (Ipp8u *)pAESGCMState;
}

void get_key(const uint8_t *sealed_blob, Ipp8u *unsealedkey128) {
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, NULL, 0,
                                       decrypt_data, &decrypt_data_len);
    memcpy(unsealedkey128, decrypt_data, KEY_SIZE);
}

sgx_status_t test_aes_key(const uint8_t *sealed_blob, size_t data_size, uint8_t *encrypted_buffer,
                          size_t buffer_size) {
    Ipp8u unsealedkey128[KEY_SIZE];
    get_key(sealed_blob, unsealedkey128);
    Ipp8u pOutPlainText[buffer_size - 12 - 16] = {};
    decrypt_object(pOutPlainText, unsealedkey128, encrypted_buffer, buffer_size);
    double *userValues = reinterpret_cast<double *>(pOutPlainText);
    size_t numValues = (buffer_size - 12 - 16) / sizeof(double);
    char buffer[100];
    for (size_t i = 0; i < numValues; ++i) {
        snprintf(buffer, sizeof(buffer), "double[%zu] = %.10f\n", i, userValues[i]);
        ocall_print_string(buffer);
    }
}

sgx_status_t seal_aes_key(uint8_t *key128, uint32_t key_size, uint8_t *sealed_blob,
                          uint32_t data_size) {
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, key_size);
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    sgx_status_t err = sgx_seal_data(0, NULL, key_size, (uint8_t *)key128, sealed_data_size,
                                     (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS) {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

void enclave_print_string(char *str_to_print) { ocall_print_string(str_to_print); }

void compute_array_average(int *numbers, size_t cnt) {
    int array_size = (int)cnt;
    int i;
    double sum = 0;
    for (i = 0; i < array_size; i++) {
        sum += numbers[i];
    }
    double average = sum / (double)array_size;
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "Avg: %.2lf\n", average);
    ocall_print_string(buffer);
}

uint32_t get_sealed_data_size() { return sgx_calc_sealed_data_size(0, sizeof(key128_blank)); }

sgx_status_t seal_data(uint8_t *sealed_blob, uint32_t data_size) {
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    sgx_status_t err =
        sgx_seal_data(0, NULL, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data,
                      sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS) {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size) {
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, NULL, 0,
                                       decrypt_data, &decrypt_data_len);
    ocall_print_string((char *)decrypt_data);
    free(decrypt_data);
    return ret;
}