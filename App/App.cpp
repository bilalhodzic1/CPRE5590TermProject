
#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <fstream>
#include <cstdint>


sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void print_byte_by_byte(const char *str, size_t len){
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", (unsigned char)str[i]);
    }
    printf("\n");
}
void print_char_by_char(const char *str, size_t len){
    for (size_t i = 0; i < len; ++i) {
        printf("%c", (unsigned char)str[i]);
    }
    printf("\n");
}

int SGX_CDECL main(int argc, char *argv[]){
    (void)(argc);
    (void)(argv);
    if(argc < 2){
        return -1;
    }
    if(initialize_enclave() < 0){
        return -1; 
    }

    if(strcmp("makekey", argv[1]) == 0){
        uint32_t sealed_data_size = 0;
        get_sealed_data_size(global_eid, &sealed_data_size);
        uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
        sgx_status_t retval;
        seal_aes_key(global_eid, &retval, temp_sealed_buf, sealed_data_size);
        std::ofstream("sealed_sym_key.txt", std::ios::binary).write((char*)temp_sealed_buf, sealed_data_size);
    }else if (strcmp("testkey", argv[1]) == 0){
        size_t fsize = get_file_size("sealed_sym_key.txt");
        uint8_t *temp_buf = (uint8_t *)malloc(fsize);
        std::ifstream("sealed_sym_key.txt", std::ios::binary).read((char*)temp_buf, fsize);
        sgx_status_t retval;
        test_aes_key(global_eid, &retval, temp_buf, fsize);
    }

    //test_aes_key(global_eid);

    // int numbers[] = {2,5,7};
    // compute_array_average(global_eid, numbers, 3);

    // char test_string[] = "Here is a test string to print in the enclave\n";
    // enclave_print_string(global_eid,test_string);

    sgx_destroy_enclave(global_eid);
    return 0;
}