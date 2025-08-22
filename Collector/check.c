#include <windows.h>
#include <stdio.h>

void read_pipe(const char *pipeName) {
    HANDLE hPipe;
    char buffer[65536];
    DWORD bytesRead;

    hPipe = CreateFileA(
        pipeName,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to connect to %s. Error: %lu\n", pipeName, GetLastError());
        return;
    }

    printf("[+] Connected to %s\n", pipeName);

    while (1) {
        BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        if (!result || bytesRead == 0) {
            printf("[!] Disconnected from %s\n", pipeName);
            break;
        }
        buffer[bytesRead] = '\0';  // Null-terminate
        printf("[%s] %s\n", pipeName, buffer);
    }

    CloseHandle(hPipe);
}

int main() {
    printf("[*] Connecting to IDS pipes...\n");
   
    read_pipe("\\\\.\\pipe\\IDS_Error");
    return 0;
}
