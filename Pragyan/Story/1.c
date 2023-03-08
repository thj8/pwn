#include <stdio.h>

int main()
{
  long t=time(0);
	long t2=t/60;
  printf("%ld\n", t);
  printf("%ld\n", t2);
	srand(t2);
	printf("%d\n", rand() % 1000);
	printf("%d\n", rand() % 1000);
	printf("%d\n", rand() % 1000);
	printf("%d\n", rand() % 1000);

	int v3;
	int v4;
	scanf("%d %d", &v4, &v3);
	printf("%d\n", v3);
	printf("%d\n", v4);
}
