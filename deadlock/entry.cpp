#define EXE
#include "../windows/global.h"

int _dl_windows_launch()
{
    auto test = memory::_malloc(0x1000);
    std::cout << "test " << test.get_decrypted() << "\n";

    io::json_state state;
    state.set_current_category("Lmao");

    auto some_val = 1;

    state.push_var("name", & some_val);
    std::cout << state.convert_json_state_to_json_string() << "\n";

    return 0;
}


// Dummy main function for demonstration


//void _dl_windows_launch()
//{

//}
