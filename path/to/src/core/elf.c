// elf.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Define a struct to represent an ELF file
typedef struct {
    char* filename;
    bool is_script;
} ElfFile;

// Function to load an ELF file
int elf_load(ElfFile* elf, const char* filename) {
    // Open the file in read mode
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening file: %s\n", filename);
        return -1;
    }

    // Read the ELF header
    char elf_header[1024];
    if (fread(elf_header, 1, sizeof(elf_header), file) != sizeof(elf_header)) {
        printf("Error reading ELF header: %s\n", filename);
        fclose(file);
        return -1;
    }

    // Check if the file is a script
    if (strstr(elf_header, "#!") != NULL) {
        elf->is_script = true;
    } else {
        elf->is_script = false;
    }

    fclose(file);
    return 0;
}

// Function to check if a file is a script
bool is_script(const char* filename) {
    ElfFile elf;
    elf.filename = filename;
    elf.is_script = false;

    if (elf_load(&elf, filename) == 0) {
        return elf.is_script;
    } else {
        return false;
    }
}