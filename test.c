#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(){

	int arr[2][5] = {
		{1,2,3,4,5},
		{6,7,8,9,10}
	};

	int arr2[];
	memcpy(arr2[5],arr[0],sizeof(arr2[0]));


	int i;
	for (i=0;i<5;i++){	
		printf("%d", arr2[i]);
	}

	return 0;
}
