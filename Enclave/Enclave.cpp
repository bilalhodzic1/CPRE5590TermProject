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

bool generate_random_IV(Ipp8u *iv, int ivSize = IV_LEN) {
    return sgx_read_rand(iv, ivSize) == SGX_SUCCESS;
}

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

sgx_status_t perform_aggregation(const uint8_t *sealed_blob, size_t data_size,
                                 uint8_t *encrypted_buffer, size_t buffer_size, int type,
                                 uint8_t *output_buffer, uint32_t output_buffer_size) {
    Ipp8u unsealedkey128[KEY_SIZE];
    get_key(sealed_blob, unsealedkey128);
    Ipp8u pOutPlainText[buffer_size - 12 - 16] = {};
    decrypt_object(pOutPlainText, unsealedkey128, encrypted_buffer, buffer_size);
    double *userValues = reinterpret_cast<double *>(pOutPlainText);
    size_t numValues = (buffer_size - 12 - 16) / sizeof(double);
    double agg_result = 0.0;
    if (type == 1) {
        double summation = 0.0;
        for (int i = 0; i < numValues; i++) {
            summation += userValues[i];
        }
        agg_result = summation;
    } else if (type == 2) {
        double max = userValues[0];
        for (int i = 0; i < numValues; i++) {
            if (userValues[i] > max) {
                max = userValues[i];
            }
        }
        agg_result = max;
    } else if (type == 3) {
        double min = userValues[0];
        for (int i = 0; i < numValues; i++) {
            if (userValues[i] < min) {
                min = userValues[i];
            }
        }
        agg_result = min;
    } else if (type == 4) {
        double summation = 0.0;
        for (int i = 0; i < numValues; i++) {
            summation += userValues[i];
        }
        agg_result = summation / (double)numValues;
    }
    Ipp8u encryption_iv[12];
    generate_random_IV(encryption_iv);
    Ipp8u result_plaintext[sizeof(double)];
    memcpy(result_plaintext, &agg_result, sizeof(double));
    Ipp8u output_tag[16];
    Ipp8u result_ciphertext[sizeof(double)];

    int encrypt_ctx_size = 0;
    ippsAES_GCMGetSize(&encrypt_ctx_size);
    IppsAES_GCMState *output_context = (IppsAES_GCMState *)(new Ipp8u[encrypt_ctx_size]);
    ippsAES_GCMInit(unsealedkey128, KEY_SIZE, output_context, encrypt_ctx_size);
    ippsAES_GCMStart(encryption_iv, IV_LEN, NULL, 0, output_context);
    ippsAES_GCMEncrypt(result_plaintext, result_ciphertext, sizeof(double), output_context);
    ippsAES_GCMGetTag(output_tag, sizeof(output_tag), output_context);
    memcpy(output_buffer, encryption_iv, IV_LEN);
    memcpy(output_buffer + IV_LEN, result_ciphertext, sizeof(double));
    memcpy(output_buffer + IV_LEN + sizeof(double), output_tag, sizeof(output_tag));
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