#include "routines.h"
#include "../windows/global.h"
#include "watcher/intercept_and_watch.h"

void watchdog_routines::patch_walk()
{
	while (true)
	{

        watcher::hook_watch_lock.lock();

        for (int current = 0; current < watcher::vec_patch_walk.size(); current++)
        {
            auto hook = watcher::vec_patch_walk[current];

            unsigned long long patch_ul = hook.patch.get_decrypted();

            if (hook.patch.get_decrypted() != *(unsigned long long*)(hook.patch_target.get_decrypted()) && hook.enabled.get_decrypted())
            {
                unsigned long long buffer_stored = hook.patch.get_decrypted();

                if (!_memequal((void*)hook.target_function.get_decrypted(), (void*)&buffer_stored, hook.patch_size.get_decrypted()))
                {
                    std::cout << "patch violation detected\n";
                }
                   // dl_api::protection::reporting::report(reporting::watchdog_reports::wd_patch_integrity_failure, &watcher::vec_patch_walk[current]);
            }
        }

        watcher::hook_watch_lock.release();

        std::cout << "watchdog tick\n";
		threading::sleep(1000);
	}

}