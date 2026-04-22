#include <Windows.h>
#include <thread>

#define REBASE(x) x + (uintptr_t)GetModuleHandle(nullptr)

void printy()
{
    const uintptr_t StdOut_ = REBASE(0x1D96FB0); // print offset

    typedef enum { print, info, warn, error } StdOut_type;
    using _StdOut = void(__fastcall*)(StdOut_type type, const char* fmt, ...);
    auto StdOut = (_StdOut)StdOut_;

    StdOut(info, "Riviera");
    StdOut(print, "Riviera");
    StdOut(warn, "Riviera");
    StdOut(error, "Riviera");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        printy();
        //MessageBoxA(0, "hi", "hi", MB_OK | MB_TOPMOST);
    }
    return TRUE;
}