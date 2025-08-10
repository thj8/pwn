#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main() {
    // Declare variables
    int your_estimated_coolness;
    char your_name[64];

    // Disable buffering for stdin and stdout
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // Seed the random number generator with the current time
    srand(time(NULL));

    // Talk to user
    printf("Whoa there, my dude. Only the truly cool are allowed in here.\n");

    // Use the standard coolness formula to determine how cool the user is
    your_estimated_coolness = 500 + 10 * (rand() % 1000);

    // Read in the user's name
    printf("What's your name? ");
    gets(your_name);

    // Evaluate them
    printf("%s, it looks like your coolness value is %d.\n", your_name, your_estimated_coolness);
    if (your_estimated_coolness < 1500000001) {
        printf("I'm sorry, you're just not cool enough. Get lost!\n");
    } else if (your_estimated_coolness > 1500000001) {
        printf("Whoa, you're... you're actually a bit too cool for us. Sorry...\n");
    } else if (your_estimated_coolness == 1500000001) {
        printf("Wow! Radical... You're in. Have fun.\n");
        printf("Oh, right, here's the flag: %s\n", getenv("FLAG"));
    }

    return 0;
}