#include <stdio.h>
#include <unistd.h>

int main()
{   
    int i;
    printf ("PID: %d\n", (int)getpid());
    for(i = 0; i < 1000; i++) 
    {
        printf("Iteration %d\n", i);
        sleep(2);
    }
    getchar();
    printf("Exiting...\n");

    return 0;
}