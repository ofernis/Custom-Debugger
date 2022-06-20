#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "symbol.h"
#include "elf64.h"



int followFunctionOp(const char* function, char** argv) {
    int pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace_error");
            exit(1);
        }
        execl(function, argv[2], NULL); // argv[2] is the executable file name
    }
    else if (pid > 0) {
        return pid;
    }
    else {
        perror("fork_error");
        exit(1);
    }
}

void debug(int child_process_pid, unsigned long function_address) {
    int wait_status;
    int run_count = 0;

    // here we set our breakpoint when calling the followed function
    waitpid(child_process_pid, &wait_status, 0); // wait for child to stop on its first instruction
    unsigned long orig_data = ptrace(PTRACE_PEEKTEXT, child_process_pid, (void*) function_address, NULL);
    unsigned long trap_data = (data & 0xFFFFFFFFFFFFFF00) | 0xCC; // change first byte to int 3 instruction (trap)
    prtrace(PTRACE_POKETEXT, child_process_pid, (void*) function_address, trap_data);

    // let the program continue running and call followed function
    ptrace(PTRACE_CONT, child_process_pid, 0, 0);
    wait(&wait_status);
    bool is_currently_inside_followed_function = true;


    // loop over the followed function calls
    while (WIFSTOPPED(wait_status)) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        
        if (function_address == regs.rip - 1) {
            run_count++;
            //ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
            ptrace(PTRACE_POKETEXT, child_process_pid, (void*) function_address, orig_data);
            
            // set return address to the instruction the follows the breakpoint?
            Elf64_Addr ret_address = ptrace(PTRACE_PEEKTEXT, child_process_pid, (void*) regs.rsp, NULL);
            unsigned long ret_orig_data = ptrace(PTRACE_PEEKTEXT, child_process_pid, ret_address, NULL);
            unsigned long ret_trap_data = (ret_orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_process_pid, (void*) ret_address, ret_trap_data);
            
            // set rip to the instruction of the breakpoint 
            ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
            regs.rip--;
            ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);

            while(is_currently_inside_followed_function && WIFEXITED(wait_status) == false) {
                ptrace(PTRACE_SYSCALL, child_process_pid, NULL, NULL);
                wait(&wait_status);

                ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
                // check if rip is at the instruction following the breakpoint?
                if (ret_address == regs.rip - 1) { 
                    ptrace(PTRACE_SYSCALL, child_process_pid, NULL, NULL);
                    wait(&wait_status);
                    ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);

                    if(is_currently_inside_followed_function) {
                        printf("PRF:: run %d returned with %lld\n", run_count, regs.rax);
                    }
                }
                else {
                    ptrace(PTRACE_POKETEXT, child_process_pid, (void*) ret_address, ret_orig_data);

                    // set rip to the instruction of the breakpoint
                    ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
                    regs.rip--;
                    ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);

                    ptrace(PTRACE_POKETEXT, child_process_pid, (void*) function_address, trap_data);
                    is_currently_inside_followed_function = false;
                    ptrace(PTRACE_CONT, child_process_pid, 0, 0);

                    wait(&wait_status);

                    ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
                    if (ret_address == regs.rip - 1) {
                        is_currently_inside_followed_function = true;
                        break;
                    }
                    else {
                        ptrace(PTRACE_CONT, child_process_pid, 0, 0);
                    }

                }
            }
        }
        ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        if (function_address == regs.rip - 1) {
            continue;
        }
        is_currently_inside_followed_function = false;
        wait(&wait_status);
        if (WIFEXITED(wait_status)) {
            return;
        }
    }
}                                       

int main(char** argv, int argc) {
    unsigned int num_of_symbols = 0;
    char* function_name = argv[1];
    char* exec_fname = argv[2];
    long symbol_address = getSymbolAddress(function_name, exe_file_name, &num_of_symbols);
    switch (symbol_address) {
        case NOT_EXEC:
            printf("PRF:: %s not an executable!\n", function_name);
            return 0;
            break;
        case NOT_FOUND:
            printf("PRF:: %s not found!\n", function_name);
            return 0;
            break;
        case NOT_GLOBAL:
            printf("PRF:: %s is not a global symbol! :(\n", function_name);
            return 0;
            break;
        default:
            break;
    }
    int child_process_pid = followFunctionOp(exec_fname, argv);
    debug(child_process_pid, symbol_address);
    return 0;
}