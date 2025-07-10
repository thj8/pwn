#include <stdio.h>
#include <stdlib.h>

int main() {
    // Set the seed to 0x61616161
    srand(0x61616161);
    
    // Generate and print 100 random numbers
    for (int i = 0; i < 100; i++) {
        int random_number = rand() % 100 + 1;
        printf("%d,", random_number);
        
    }
    
    return 0;
}
