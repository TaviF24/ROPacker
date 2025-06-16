#include <stdio.h>
#include <unistd.h>
#include <windows.h>
int main(){
    MessageBoxA(NULL, "Hello, World!", "Popup", MB_OK);
    return 0;
}