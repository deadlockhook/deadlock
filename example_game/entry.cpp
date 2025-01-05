#include <Windows.h>

int main()

{
	LoadLibraryA("deadlock.dll");
	SuspendThread(GetCurrentThread());
	return 0;
}