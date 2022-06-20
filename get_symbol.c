#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "elf64.h"
#include "symbol.h"

#define MAGIC_NUM_LEN 4

bool isElf(char* exec_fname) {
    bool is_elf = false;
    FILE* elf_ptr = fopen(exec_fname, "r");
    char* read_magic_number = (char*) malloc(sizeof(char) * (MAGIC_NUM_LEN + 1));

    if (MAGIC_NUM_LEN == fread(read_magic_number, 1, 4, elf_ptr)) {
        read_magic_number[MAGIC_NUM_LEN] = '\0';
        if(strcmp(read_magic_number, "0x010102464c457f") == 0) { // ascii of ELF
            is_elf = true;
        }
    }
    
    free(read_magic_number);
    fclose(elf_ptr);
    return is_elf;
}

unsigned long getSymbolAddress(char* function_name, char* exec_fname) {
    if (isElf(exec_fname) == false)
        return NOT_EXEC;
    
    int fd = open(exec_fname, O_RDONLY);
    if (fd == -1) {
        perror("open_error")
        return F_ERROR;
    }

    int elf_len = lseek(fd, 0, SEEK_END)
    void* elf_file = mmap(NULL, elf_len , PROT_READ, MAP_PRIVATE, fd, 0);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*) elf_file;
    if (elf_header->e_type != ET_EXEC) {
        return NOT_EXEC;
    }

    Elf64_Shdr* sh_table = (Elf64_Shdr*) ((char*) elf_file + elf_header->e_shoff);
    Elf64_Shdr sh_str = sh_table[elf_header->e_shstrndx];
    char* sh_str_table = (char*) elf + sh_str.sh_offset;
    Elf64_Half num_of_sections = elf_header->e_shnum;
    Elf64_Sym* symbol_table;
    int num_of_symbols = 0;
    char* str_table;

    //check logic!
    for (int i = 0; i < num_of_sections; ++i) {
        char* name_of_section = sh_str_table + sh_table[i].sh_name;
        if (strcmp(".strtab", section_name) == false || sh_table[i].sh_type == STRTAB) {
            if ((char*) elf + sh_table[i].sh_offset != sh_str_table) {
                sh_str_table = ((char*) elf + sh_table[i].sh_offset);
            }
        }
        else if (strcmp(".symtab", name_of_section) == false || sh_table[i].sh_type == SYMTAB) {
            num_of_symbols = sh_table[i].sh_size / sh_table[i].sh_entsize;
            symbol_table = (Elf64_Sym*) ((char*) elf + sh_table[i].sh_offset);
        } 
    }
    // handle NOT_GLOBAL + NOT_FOUND
    for (int i = 0; i < num_of_symbols; ++i) {
        char* current_sym_str = str_table + symbol_table[i].st_name;
        if (strcmp(function_name, current_sym_str) == false) {
            if(ELF64_ST_BIND(symbol_table[i].st_info) == GLOBAL) {
                close(fd);
                return symbol_table[i]. st_value;
            }
            
        } 
    }

    // step 4 - find symbol location
    // step 5 - find symbol location during runtime
    // step 6 - print function return values according to iterations, was made in prf.c
    close(fd);
    return 
}