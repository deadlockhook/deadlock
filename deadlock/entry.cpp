#define EXE
#include "../windows/global.h"



int _dl_windows_launch()
{
    MessageBox(NULL, L"Last", L"Hello", MB_OK);
    return 0;
}


// Dummy main function for demonstration


//void _dl_windows_launch()
//{

//}
