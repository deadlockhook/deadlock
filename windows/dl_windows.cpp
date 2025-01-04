#include "global.h"

extern "C" void mainCRTStartup();

int main()
{
    return  _dl_windows_launch();
}

void _start() {
	encryption::initialize();
    windows::initialize();
    memory::initialize();
    mainCRTStartup();
}

