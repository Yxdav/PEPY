#include <stdio.h>
#include <Windows.h>

DWORD error(DWORD ErrorCode, DWORD Line)
{
    printf("[-] %ld:Error 0x%x\n", Line ,ErrorCode);
    return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{

    printf("[*] PID: %i\n",GetCurrentProcessId());
    printf("Bye world\n");
    return EXIT_SUCCESS;
}