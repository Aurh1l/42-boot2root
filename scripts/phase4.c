#include <stdio.h>
#include <stdlib.h>
int func4(int param_1)

{
	int iVar1;
	int iVar2;

	if (param_1 < 2) {
		iVar2 = 1;
	}
	else {
		iVar1 = func4(param_1 + -1);
		iVar2 = func4(param_1 + -2);
		iVar2 = iVar2 + iVar1;
	}
	return iVar2;
}

int main(void) {
	int i = 3;

	while (1) {
		if (func4(i) == 55) {
			dprintf(1, "The correcteur number is %d.\n", i);
			return 0;
		}
		i++;
	}
	return 0;
}
