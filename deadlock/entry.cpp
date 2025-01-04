#define EXE
#include "../windows/global.h"

int _dl_windows_launch()
{
    auto test = memory::_malloc(0x1000);
    std::cout << "test " << test.get_decrypted() << "\n";
    return 0;
}


// Dummy main function for demonstration


//void _dl_windows_launch()
//{

//}
