#include <windows.h>
#include <iostream>

int main() {
    // Session 0 isolation - user session helper process
    // Registers AddClipboardFormatListener and sends to named pipe
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
