#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "elf64.h"
#include <fcntl.h>
#include "get_symbol.h"
#include "sys/mman.h"
#include <assert.h>
#include <sys/reg.h>
#include <sys/user.h>
#define GLOBAL 1
#define MAGIC_NUM_LEN 4
#define ET_EXEC 2
#define SYMTAB 2
#define STRTAB 3

static bool isItElf(char *exec_fname);
unsigned long getSymbolAddress(char *function_name, char *exec_fname, bool *is_dynamic);

unsigned long getSymbolAddress(char *function_name, char *exec_fname, bool *is_dynamic)
{
    if (isItElf(exec_fname) == false)
    {
        return NOT_EXEC;
   }

    int fd = open(exec_fname, O_RDONLY);
    if (fd == -1)
    {
        perror("open_error");
        return F_ERROR;
    }

    int elf_len = lseek(fd, 0, SEEK_END); /* move the file position to the end and returns the new position - the end position - the size of the file.*/
    void *elf_file = mmap(NULL, elf_len, PROT_READ, MAP_PRIVATE, fd, 0);
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *)elf_file;
    if (elf_header->e_type != ET_EXEC)
    {
        return NOT_EXEC;
    }

    /* e_shoff - offset from the begining of the file to the section table */
    Elf64_Shdr *sh_table = (Elf64_Shdr *)((char *)elf_file + elf_header->e_shoff); /* זה כמו מצביע לאינט - מערך שיש בו הרבה איברים מסוג אינט*/
    /* e_shstrndx - section header string table indext - being used to resolved the names of the sections containg in the file */
    Elf64_Shdr sh_str = sh_table[elf_header->e_shstrndx]; /*זה המספר האינט עצמו*/ /* now we have  the section that describe where we can get the names of the section hear in the sht  */
    /*כעת המשתמש מעלה מחזיק את הסקשין  הדר של הסמלים*/
    /* תחשוב שבטבלת הסקשיין הדרס יש מלא סקשן הדרים שונים*/
    char *sh_str_table = (char *)elf_file + sh_str.sh_offset;
    /* בסקשן הדר של המחרוזות אפשר למצוא אופסט של איפה נמצא המערך שממש מכיר את המחרוזות */
    Elf64_Half num_of_sections = elf_header->e_shnum; /* how much section headrs do we have in section headr table */
    Elf64_Sym *symbol_table;
    int num_of_symbols = 0;
    char *symb_str_table;
    Elf64_Rela *rela_tble;
    char *dynamic_str;
    Elf64_Sym *dyn_symbol;
    Elf64_Xword size_rela;
    Elf64_Xword number_of_entry_in_rela_tble;
    unsigned long long Got_relativ_addres;

    for (int i = 0; i < num_of_sections; ++i)
    {
        char *name_of_section = sh_str_table + sh_table[i].sh_name /*its just an offset to the str_table to find the real name*/;
        if (strcmp(".strtab", name_of_section) == 0) // || sh_table[i].sh_type == STRTAB)
        {
            if ((char *)elf_file + sh_table[i].sh_offset != sh_str_table) /* there might be more than one section heared of STARTAB*/
            {
                symb_str_table = ((char *)elf_file + sh_table[i].sh_offset);
            }
        }
        else if (strcmp(".symtab", name_of_section) == 0 || sh_table[i].sh_type == SYMTAB)
        {
            num_of_symbols = sh_table[i].sh_size / sh_table[i].sh_entsize;
            symbol_table = (Elf64_Sym *)((char *)elf_file + sh_table[i].sh_offset);
        }
        else if (strcmp(".dynsym", name_of_section) == 0)
        {
            dyn_symbol = (Elf64_Sym *)((char *)elf_file + sh_table[i].sh_offset);
        }
        else if (strcmp(".dynstr", name_of_section) == 0)
        {
            dynamic_str = ((char *)elf_file + sh_table[i].sh_offset);
        }
        else if (strcmp(".rela.plt", name_of_section) == 0)
        {
            size_rela = sh_table[i].sh_size;
            number_of_entry_in_rela_tble = (size_rela / sh_table[i].sh_entsize);
            rela_tble = (Elf64_Rela *)((char *)elf_file + sh_table[i].sh_offset);
        }
    }

    int times_of_func = 0;
    // handle NOT_GLOBAL + NOT_FOUND
    for (int i = 0; i < num_of_symbols; i++)
    {
        char *current_sym_str = symb_str_table + symbol_table[i].st_name;
        if (strcmp(function_name, current_sym_str) == 0)
        {
            if (ELF64_ST_BIND(symbol_table[i].st_info) == GLOBAL)
            {                                                                       
                *is_dynamic = ((Elf64_Half)symbol_table[i].st_shndx == SHN_UNDEF) ? 1 : 0;
                if (*is_dynamic == true)
                {
                    for (int i = 0; i < number_of_entry_in_rela_tble; i++)
                    {
                        if (strcmp(dynamic_str + dyn_symbol[ELF64_R_SYM(rela_tble[i].r_info)].st_name, function_name) == 0)
                        {
                            Got_relativ_addres = rela_tble[i].r_offset;
                        }
                    }
                    close(fd);
                    return Got_relativ_addres;
                }
                close(fd);
                return symbol_table[i].st_value;
                times_of_func += 1;
            }
            else
            {
                times_of_func += 1;
            }
        }
    }

    close(fd);
    if (times_of_func == 0)
    {
        return NOT_FOUND;
    }
    else
    {
        return NOT_GLOBAL;
    }
}

static bool isItElf(char *exec_fname)
{
    // printf("%s",exec_fname);
    bool is_file_an_elf_file = false;
    FILE * elf_ptr = fopen(exec_fname, "r");
    char * read_magic_number = (char*)malloc(sizeof(char) * (MAGIC_NUM_LEN + 1));

    if (MAGIC_NUM_LEN == fread(read_magic_number, 1, 4, elf_ptr))
    {
        read_magic_number[MAGIC_NUM_LEN] = '\0';

        if (strcmp((read_magic_number + 1), "ELF") == 0)
        {
            is_file_an_elf_file = true;
        }
    }

    free(read_magic_number);
    fclose(elf_ptr);
    return is_file_an_elf_file;
}