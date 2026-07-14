// exec.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "elf.h"

// Function to execute a file
int exec_file(const char* filename) {
    // Check if the file is a script
    if (is_script(filename)) {
        // If the file is a script, do not apply set-user-ID/set-group-ID bits
        printf("File %s is a script, skipping set-user-ID/set-group-ID bits\n", filename);
    } else {
        // If the file is not a script, apply set-user-ID/set-group-ID bits
        printf("File %s is not a script, applying set-user-ID/set-group-ID bits\n", filename);
    }

    // Simulate executing the file
    printf("Executing file %s\n", filename);
    return 0;
}