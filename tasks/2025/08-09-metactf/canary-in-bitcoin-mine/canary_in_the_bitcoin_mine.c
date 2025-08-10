#include <stdio.h>
#include <string.h>
#include <stdbool.h>

void win() {
    printf("Well done, you've earned the flag!\n");
    fflush(stdout); // Ensure output is flushed
    FILE *flag_file = fopen("flag.txt", "r");
    if (flag_file != NULL) {
        char flag_content[100];
        while (fgets(flag_content, sizeof(flag_content), flag_file) != NULL) {
            printf("%s", flag_content);
            fflush(stdout); // Ensure output is flushed
        }
        fclose(flag_file);
        printf("\n");
        fflush(stdout); // Ensure output is flushed
    } else {
        printf("flag.txt file not found\n");
        fflush(stdout); // Ensure output is flushed
    }
}

void hexdump(void *addr, int len) {
    int i;
    unsigned char *pc = (unsigned char*)addr;

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  ");
            for (int j = i - 16; j < i; j++) {
                if (j >= 0 && j < len) {
                    printf("%c", (pc[j] >= 32 && pc[j] <= 126) ? pc[j] : '.');
                }
            }
            printf("\n");
            printf("%04x ", i);
        }
        printf(" %02x", pc[i]);
    }

    // Print the final ASCII representation for the last line
    int remainder = i % 16;
    if (remainder != 0) {
        for (int j = 0; j < 16 - remainder; j++) {
            printf("   ");
        }
        printf("  ");
        for (int j = i - remainder; j < i; j++) {
            printf("%c", (pc[j] >= 32 && pc[j] <= 126) ? pc[j] : '.');
        }
    }
    printf("\n");
}

int main() {
    struct {
        char mine[64];
        int canary;
        bool earnedFlag;
    } mineshaft;
    char debris[256];

    mineshaft.canary = 0x44524942; //BIRD in little endian
    mineshaft.earnedFlag = false; //set this bool to false

    printf("Welcome to the MetaCTF bitcoin mine, we have a flag you can earn, but it's guarded by our trusty canary!\n\n");
    fflush(stdout); // Ensure output is flushed

    // Zero out the buffer
    memset(mineshaft.mine, 0, sizeof(mineshaft.mine));

    printf("Memory layout before input:");
    fflush(stdout); // Ensure output is flushed
    hexdump(&mineshaft, sizeof(mineshaft));

    printf("\n");
    fflush(stdout); // Ensure output is flushed

    while(1)
    {
        printf("Place some characters into the mine: ");
        fflush(stdout); // Ensure output is flushed
        extern char *gets(char *); // Explicit declaration of gets to allow compilation
        gets(mineshaft.mine);

        printf("\nMemory layout after input:");
        fflush(stdout); // Ensure output is flushed
        hexdump(&mineshaft, sizeof(mineshaft));

        if (mineshaft.canary != 0x44524942) { // "BIRD" in little-endian
            printf("Oh no, the canary died! We need to evacuate immediately!\n\n");
            fflush(stdout); // Ensure output is flushed
            return 0;
        } else {
            printf("Canary is alive.\n");
            fflush(stdout); // Ensure output is flushed
            if (mineshaft.earnedFlag) {
                win();
            } else {
                printf("Looks like you haven't earned your flag yet though...\n\n");
                fflush(stdout); // Ensure output is flushed
            }
        }
    }
}
