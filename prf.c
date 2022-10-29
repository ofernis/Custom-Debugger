#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "elf64.h"
#include "get_symbol.h"
#include "sys/mman.h"
#include "unistd.h"
#include <stdbool.h>
#include <sys/reg.h>
#include <sys/user.h>

int followFunctionOp(const char *function, char **argv);

void debug(int child_process_pid, unsigned long function_address, bool is_dynamic);

int main(int argc, char **argv)
{
    
    char *function_name = argv[1];
    char *exec_fname = argv[2];
    bool is_dynamic = false;
    
    unsigned long symbol_address = getSymbolAddress(function_name, exec_fname, &is_dynamic);
    // printf("\n%lu\n",symbol_address);
     //return 0;  
    switch (symbol_address)
    {
    case NOT_EXEC:
        printf("PRF:: %s not an executable!\n", exec_fname);
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

    pid_t child_process_pid = followFunctionOp(exec_fname, argv);
    debug(child_process_pid, symbol_address, is_dynamic);
    return 0;
}

pid_t followFunctionOp(const char *function, char **argv)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork_error");
        exit(1);
    }
    else if (pid == 0) /* im the son*/
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace_error");
            exit(1);
        }

        execl(function, argv[2], NULL); // argv[2] is the executable file name
    }
    else /* im the ded*/
    {
        return pid;
    }
}

void debug(pid_t child_process_pid, unsigned long function_address, bool is_dynamic)
{
    int wait_status;
    waitpid(child_process_pid, &wait_status, 0); // wait for child to stop on its first instruction

    int call_counter = 1;
    unsigned long real_function_address;
    unsigned long function_ret_address;
    unsigned long function_address_for_firts_iteration;
    unsigned long original_data;
    struct user_regs_struct regs;
    unsigned long long relevant_rsp;
    //  printf("is_dynamic is: %d\n\n\n\n",(int)is_dynamic);
    if (is_dynamic == true) // than func_add is actually the addres of the got entry addres for func.
    {
        // if we are dynamic so function_address dose not contain the addres of the function but the addres of the got entery related to the plt adders that relate to the function.

        function_address_for_firts_iteration = ptrace(PTRACE_PEEKTEXT, child_process_pid, function_address, NULL); // get the addres of the trampoline from Got.
        original_data = ptrace(PTRACE_PEEKTEXT, child_process_pid, function_address_for_firts_iteration, NULL);    // backup the opcode in that adress.
        unsigned long trap_data_only_for_first_iteration = (original_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_process_pid, function_address_for_firts_iteration, trap_data_only_for_first_iteration);
        ptrace(PTRACE_CONT, child_process_pid, 0, 0);
        wait(&wait_status);
        ptrace(PTRACE_POKETEXT, child_process_pid, function_address_for_firts_iteration, original_data);
        ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        regs.rip--;
        relevant_rsp = 8 + regs.rsp; 
        ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);
        unsigned long orig_data_addres_2 = ptrace(PTRACE_PEEKTEXT, child_process_pid, regs.rsp, NULL);
        unsigned long orig_data_2 = ptrace(PTRACE_PEEKTEXT, child_process_pid, orig_data_addres_2, NULL);
        unsigned long trap_data_2 = (orig_data_2 & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_process_pid, orig_data_addres_2, trap_data_2);
        unsigned long ret_add = orig_data_addres_2;
        ptrace(PTRACE_CONT, child_process_pid, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        while (regs.rsp != relevant_rsp && !WIFEXITED(wait_status))
        {
             ptrace(PTRACE_POKETEXT, child_process_pid, orig_data_addres_2, orig_data_2);
             regs.rip--;
             ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);
             ptrace(PTRACE_SINGLESTEP, child_process_pid, NULL, NULL);
             wait(&wait_status);
             ptrace(PTRACE_POKETEXT, child_process_pid, orig_data_addres_2, trap_data_2);
             ptrace(PTRACE_CONT, child_process_pid, NULL, NULL);
             wait(&wait_status);
             ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        }
        regs.rip--;
        printf("PRF:: run #%d returned with %d\n", call_counter++, (int)regs.rax);
        ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);
        ptrace(PTRACE_POKETEXT, child_process_pid, ret_add, orig_data_2);
        // taking the function addres from the got after linker updated it.
        function_address = ptrace(PTRACE_PEEKTEXT, child_process_pid, function_address, NULL);
    }

    /* not dynamic */
    // printf("\n\n\n1%lu\n\n\n",function_address);
    unsigned long orig_data = ptrace(PTRACE_PEEKTEXT, child_process_pid, function_address, NULL);
    unsigned long trap_data = (orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC; // change first byte to int 3 instruction (trap)
                                                                       // ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
    ptrace(PTRACE_POKETEXT, child_process_pid, function_address, trap_data);
    /*  if we would support recorsiv calls we would put here singel_step? */
    ptrace(PTRACE_CONT, child_process_pid, NULL, NULL);
    wait(&wait_status);
    
    while (!WIFEXITED(wait_status))
    { 
        // bool is_currently_inside_followed_function = true;
        ptrace(PTRACE_POKETEXT, child_process_pid, function_address, orig_data);

        ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        
        regs.rip--;
        relevant_rsp = 8 + regs.rsp; 

        //  printf("\n\n0-%lu\n\n\n",(unsigned long)(regs.rip));
        //   printf("\n\n0-%lu\n\n\n",(unsigned long)(regs.rsp));
        ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs); // if we didnt keep moving after set regs so they will not change right?
        unsigned long orig_data_addres_2 = ptrace(PTRACE_PEEKTEXT, child_process_pid, regs.rsp, NULL);
        unsigned long orig_data_2 = ptrace(PTRACE_PEEKTEXT, child_process_pid, orig_data_addres_2, NULL);
        unsigned long trap_data_2 = (orig_data_2 & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_process_pid, orig_data_addres_2, trap_data_2);
        unsigned long ret_add = orig_data_addres_2; // addres after returning from foo.
        // printf("\n\n2%luo\n\n\n",(unsigned long)(regs.rip));
        // printf("\n\n3%lu\n\n",(unsigned long)(regs.rsp));
        ptrace(PTRACE_CONT, child_process_pid, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        while (regs.rsp != relevant_rsp && !WIFEXITED(wait_status))
        {
             ptrace(PTRACE_POKETEXT, child_process_pid, orig_data_addres_2, orig_data_2);
             regs.rip--;
             ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);
             ptrace(PTRACE_SINGLESTEP, child_process_pid, NULL, NULL);
             wait(&wait_status);
             ptrace(PTRACE_POKETEXT, child_process_pid, orig_data_addres_2, trap_data_2);
             ptrace(PTRACE_CONT, child_process_pid, NULL, NULL);
             wait(&wait_status);
             ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
        }
        
        // printf("\n\n\n4%lu\n\n\n",(unsigned long)(regs.rip));
        regs.rip--;
        printf("PRF:: run #%d returned with %d\n", call_counter++, (int)regs.rax);
        ptrace(PTRACE_SETREGS, child_process_pid, NULL, &regs);
        ptrace(PTRACE_POKETEXT, child_process_pid, ret_add /*or regs.rip*/, orig_data_2);
        // printf("\n\n\n5%lu\n\n\n",(unsigned long)(ret_add));
        // printf("\n\n\n6%lu\n\n\n",(unsigned long)(regs.rip));//regs.rip
        // ptrace(PTRACE_SINGLESTEP, child_process_pid, NULL, NULL);
        // wait(&wait_status);

        ///////////////////////////////// ptrace(PTRACE_GETREGS, child_process_pid, NULL, &regs);
         orig_data = ptrace(PTRACE_PEEKTEXT, child_process_pid, function_address, NULL);
         trap_data = (orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_process_pid, function_address, trap_data);
        // is_currently_inside_followed_function = false;
        ptrace(PTRACE_CONT, child_process_pid, NULL, NULL);
        wait(&wait_status);
        // if (WIFEXITED(wait_status))
        // {
        //    return;
        // }
        // if(call_counter==2)
        // {
        //   return;
        // }
    }
    return;
}