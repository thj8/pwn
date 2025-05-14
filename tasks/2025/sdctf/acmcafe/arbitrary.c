#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void main_loop() {
	printf("Welcome to ACM Cafe!\n\n");

	int attempts = 5;
	char buffer[0x10];
	unsigned long addr, value;

	while (attempts > 0) {
		printf("What will you be ordering? ");
		fgets(buffer, sizeof(buffer), stdin);
		addr = strtoul(buffer, NULL, 16);
		printf("Oh! I just love 0x%lx, great pick!\n", *(unsigned long*)addr);

		printf("If you could go anywhere, where would you go? ");
		fgets(buffer, sizeof(buffer), stdin);
		addr = strtoul(buffer, NULL, 16);
		printf("What would you bring there? ");
		fgets(buffer, sizeof(buffer), stdin);
		value = strtoul(buffer, NULL, 16);
		*(unsigned long*)addr = value;
		printf("Hmm, that's not what I would have brought, but that's okay!");

		attempts--;
	}
}

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	main_loop();
	puts("\nCome again soon!");
	return 0;
}