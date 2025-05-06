#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <seccomp.h>


__attribute__((constructor)) void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void setup_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW); // allow all by default

    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);


    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);

    seccomp_load(ctx);
}

void vuln() {
    char buf[64];
    puts("Input:");
    read(0, buf, 256);
}

void freestuff(){
    asm("pop %rdi; ret;");
}

void jack();

int main() {
    setup_seccomp();
    jack();
    vuln();
    return 0;
}
