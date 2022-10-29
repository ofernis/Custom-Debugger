#ifndef GET_SYMBOL_H
#define GET_SYMBOL_H
#include <assert.h>
#include <stdbool.h>
enum sym_res_t { NOT_EXEC = 1, NOT_FOUND, NOT_GLOBAL, F_ERROR };

unsigned long getSymbolAddress(char* function_name, char* exec_fname, bool* is_dynamic);

#endif /* GET_SYMBOL*/