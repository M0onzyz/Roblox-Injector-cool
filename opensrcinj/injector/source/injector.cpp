#include <Windows.h>
#include <iostream>
#include "helper/helper.hpp"
#include "helper/nthelper.hpp"
#include "helper/utilhelper.hpp"
#include "helper/syshelper.hpp"

int main() {
    init_nt();
    if (!init_sys()) { std::cout << "Sys init failed" << std::endl; return 1; }

    auto info = find_p(L"RobloxPlayerBeta.exe");
    if (!info) { std::cout << "roblox isn't running" << std::endl; return 1; }

    ctx::p = (DWORD)(ULONG_PTR)info->UniqueProcessId;
    ctx::h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ctx::p);
    if (!ctx::h || ctx::h == INVALID_HANDLE_VALUE) { std::cout << "openproc failed" << std::endl; return 1; }

    uintptr_t t = read_f("module.dll");
    if (!t) { std::cout << "failed to read dll" << std::endl; return 1; }

    DWORD moduleImgSize = get_h(t)->OptionalHeader.SizeOfImage;
    uintptr_t rsv = ::load_l("C:\\Windows\\System32\\d3d10warp.dll", ctx::h);
    if (!rsv) { std::cout << "stomp failed" << std::endl; return 1; }

    IMAGE_DOS_HEADER potDos{};
    IMAGE_NT_HEADERS64 potNt{};
    if (nt_rvm(ctx::h, (PVOID)rsv, &potDos, sizeof(potDos)) && nt_rvm(ctx::h, (PVOID)(rsv + potDos.e_lfanew), &potNt, sizeof(potNt))) {
        if (potNt.OptionalHeader.SizeOfImage < moduleImgSize) { std::cout << "stomp target is too small" << std::endl; return 1; }
    }

    MODULEENTRY32W hyp{};
    for (int i = 0; i < 60; ++i) {
        Sleep(50);
        hyp = get_m_ext(ctx::p, L"RobloxPlayerBeta.dll");
        if (hyp.modBaseAddr) break;
    }
    if (!hyp.modBaseAddr) { std::cout << "waiting for target dll" << std::endl; return 1; }

    auto ldr = std::make_unique<c_ldr>();
    ldr->init(ctx::p, ctx::h, (uintptr_t)hyp.modBaseAddr, rsv);
    ldr->map("module.dll", rsv);

    std::cout << "injected" << std::endl;
    Sleep(1500);
    return 0;
}