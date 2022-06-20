#ifndef GET_SYMBOL_H
#define GET_SYMBOL_H

enum sym_res_t { NOT_EXEC, NOT_FOUND, NOT_GLOBAL, F_ERROR };

unsigned long getSymbolAddress(char* function_name, char* exec_fname);

#endif