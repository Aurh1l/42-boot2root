#include <strings.h>
#include <stdio.h>
#include <stdint.h>

char *password = "giants";
char *key = "isrveawhobpnutfg";

int phase_5(int index, int c)
{
	int32_t result = c & 0xf;
	if (password[index] == key[result]) {
		return 1;
	}
	return 0;
}

int main(void) {
	char solution[7];

	bzero(solution, 6);

	int index = 0;
	int c;

	while (index < 6) {
		c = 98;
		while (c < 123) {
			if (phase_5(index, c)) {
				solution[index] = (char)c;
				break;
			}
			c++;
		}
		index++;
	}

	dprintf(1, "The solution to solve phase 5 is: %s\n", solution);
	return 0;
}