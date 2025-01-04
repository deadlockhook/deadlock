#pragma once

#ifdef DL_ENABLE_VIRTUALIZATION
#include "../../../../../Virtualizer/Include/C/VirtualizerSDK.h"


#define vm_mutate_start VIRTUALIZER_MUTATE_ONLY_START
#define vm_mutate_end VIRTUALIZER_MUTATE_ONLY_END

#define vm_low_start VIRTUALIZER_TIGER_RED_START
#define vm_low_end VIRTUALIZER_TIGER_RED_END

#define vm_high_start VIRTUALIZER_LION_BLACK_START
#define vm_high_end VIRTUALIZER_LION_BLACK_END

#else

#define vm_mutate_start 
#define vm_mutate_end 

#define vm_low_start 
#define vm_low_end 

#define vm_high_start 
#define vm_high_end 

#endif