// tests/exec.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "exec.h"

// Function to test executing a script
void test_execute_script() {
    const char* filename = "script.sh";
    if (exec_file(filename) == 0) {
        printf("Test passed: script executed successfully\n");
    } else {
        printf("Test failed: script execution failed\n");
    }
}

// Function to test executing a non-script
void test_execute_non_script() {
    const char* filename = "non_script";
    if (exec_file(filename) == 0) {
        printf("Test passed: non-script executed successfully\n");
    } else {
        printf("Test failed: non-script execution failed\n");
    }
}

int main() {
    test_execute_script();
    test_execute_non_script();
    return 0;
}