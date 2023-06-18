#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h> 

#include <asm/prctl.h>
#include <sys/syscall.h>

#include <linux/elf.h>

#include "hde64.h"

static unsigned char blob[] = 
    "\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x0F\x22\xC0\x0F\xA2\xF4";

static char cpu_vendor[12] = "UserlandVCPU";

struct vmdesc {
    struct user_regs_struct x86_64_r;
    struct iovec io;

    unsigned long long cr0;

    void *map;
    pid_t pid;
};

static void vmlaunch(struct vmdesc *desc)
{
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    raise(SIGSTOP);
}

static void hyperlaunch(struct vmdesc *desc)
{
    hde64s instruction;
    int state = 0;
    int status = 1;

    while (status) {
        wait(&state);
        ptrace(PTRACE_GETREGSET, desc->pid, NT_PRSTATUS, &desc->io);

        /*
         * initialization
         */
        if (WSTOPSIG(state) == SIGSTOP) {
            /*
             * copy blob into memory and set rip
             */
            memcpy(desc->map, blob, sizeof(blob));
            desc->x86_64_r.rip = (uint64_t)desc->map;

            ptrace(PTRACE_SETREGSET, desc->pid, NT_PRSTATUS, &desc->io);
            ptrace(PTRACE_CONT, desc->pid, NULL, NULL);
            continue;
        }

        unsigned int length = hde64_disasm((void*)desc->x86_64_r.rip, &instruction);

        switch (instruction.opcode) {
        case 0x0f:
            switch (instruction.opcode2) {
            case 0x05:
                /* we only reach this point if syscall 'exit' is invoked */
                break;
            case 0x22:
                /* encoding ignored b/c tiny demo */
                desc->cr0 = desc->x86_64_r.rax;
                break;
            case 0xa2:
                /* limitted functionality b/c tiny demo */
                desc->x86_64_r.rbx = *(int*)&cpu_vendor[0];
                desc->x86_64_r.rdx = *(int*)&cpu_vendor[4];
                desc->x86_64_r.rcx = *(int*)&cpu_vendor[8];
                break;
            };
            break;
        
        case 0xf4:
            status = 0;
            continue;
        }

        desc->x86_64_r.rip += length;

        ptrace(PTRACE_SETREGSET, desc->pid, NT_PRSTATUS, &desc->io);
        ptrace(PTRACE_CONT, desc->pid, NULL, NULL);
    }

    kill(desc->pid, SIGKILL);
}

static char *get_vendor_string(int a, int b, int c)
{
    char *vendor = calloc(1, 13);

    *(int*)&vendor[0] = a;
    *(int*)&vendor[4] = b;
    *(int*)&vendor[8] = c;

    return vendor;
}

void static inline __cpuid(int* regs, int i) 
{
    asm volatile
      ("cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
       : "a" (i), "c" (0));
}

int main()
{
    struct vmdesc desc;

    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);

    desc.map = mmap((void*)0x10000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    desc.pid = fork();

    desc.io.iov_base = &desc.x86_64_r;
    desc.io.iov_len = sizeof(desc.x86_64_r);

    if (desc.pid == 0)
        vmlaunch(&desc);
    else
        hyperlaunch(&desc);

    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);

    printf("rax: %llx\ncr0: %llx\n", desc.x86_64_r.rax, desc.cr0);

    int regs[4];
    __cpuid(regs, 0);

    printf("host cpuid vendor string: %s\n", get_vendor_string(regs[1], regs[3], regs[2]));
    printf("guest cpuid vendor string: %s\n", get_vendor_string(desc.x86_64_r.rbx, desc.x86_64_r.rdx, desc.x86_64_r.rcx));

    return 0;
}