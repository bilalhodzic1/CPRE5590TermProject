#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

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
