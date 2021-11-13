# roughbuff

A buffer overflow tool for simple stack based buffer overflows. Developed as I learn more about buffer overflows.

## Instructions

```
usage: roughbuff.py [-h] [-B]
                    {fuzz,pattern-find,pattern-create,pattern-send,badchars-send,badchars-create,payload-send}
                    ...
A rough buffer overflow tool for simple stack based buffer overflows. Run one
of the positional argument modes with -h for more details

positional arguments:
  {fuzz,pattern-find,pattern-create,pattern-send,badchars-send,badchars-create,payload-send}

options:
  -h, --help            show this help message and exit
  -B, --hide-banner
```

### Fuzzing

```
usage: roughbuff.py fuzz [-h] -t TARGET -p PORT [-P PREFIX] [-c CHAR]
                         [-T TIMEOUT] [-f POSTFIX] [-s STEP] [-b BEGIN]
                         [-e END] [-S SLEEP]

Fuzzer to send payloads of increasing sizes to the target.

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        (required) Target IP address or hostname
  -p PORT, --port PORT  (required) Target port
  -P PREFIX, --prefix PREFIX
                        Buffer prefix
  -c CHAR, --char CHAR  Buffer character (default: A)
  -T TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds (default: 5)
  -f POSTFIX, --postfix POSTFIX
                        Postfix string
  -s STEP, --step STEP  Number of bytes to increase buffer by each fuzz
                        (default: 100)
  -b BEGIN, --begin BEGIN
                        Start buffer size in bytes (default: 100)
  -e END, --end END     Max buffer size to fuzz in bytes
  -S SLEEP, --sleep SLEEP
                        Sleep time in seconds between each fuzz (default: 1)
```

### Pattern Find

```
usage: roughbuff.py pattern-find [-h] -l LENGTH -q QUERY

Find index of hex pattern from cyclical payload pattern

options:
  -h, --help            show this help message and exit
  -l LENGTH, --length LENGTH
                        (requied) Pattern length in bytes
  -q QUERY, --query QUERY
                        (required) String to search for
```

### Pattern Create

```
usage: roughbuff.py pattern-create [-h] -l LENGTH

Create cyclical pattern of a specific length

options:
  -h, --help            show this help message and exit
  -l LENGTH, --length LENGTH
                        (required) Pattern length in bytes
```

### Pattern Send

```
usage: roughbuff.py pattern-send [-h] -t TARGET -p PORT [-P PREFIX] [-c CHAR]
                                 [-T TIMEOUT] [-f POSTFIX] -l LENGTH

Send cyclical pattern of a specific length to target

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        (required) Target IP address or hostname
  -p PORT, --port PORT  (required) Target port
  -P PREFIX, --prefix PREFIX
                        Buffer prefix
  -c CHAR, --char CHAR  Buffer character (default: A)
  -T TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds (default: 5)
  -f POSTFIX, --postfix POSTFIX
                        Postfix string
  -l LENGTH, --length LENGTH
                        (required) Pattern length in bytes
```

### BadChars Send

```
usage: roughbuff.py badchars-send [-h] -t TARGET -p PORT [-P PREFIX] [-c CHAR]
                                  [-T TIMEOUT] [-f POSTFIX] -o OFFSET [-e EIP]
                                  -b BADCHARS [BADCHARS ...]

Send BadChar array to target

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        (required) Target IP address or hostname
  -p PORT, --port PORT  (required) Target port
  -P PREFIX, --prefix PREFIX
                        Buffer prefix
  -c CHAR, --char CHAR  Buffer character (default: A)
  -T TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds (default: 5)
  -f POSTFIX, --postfix POSTFIX
                        Postfix string
  -o OFFSET, --offset OFFSET
                        (required) Buffer size required to rewrite EIP in
                        bytes
  -e EIP, --eip EIP     EIP in hex (big endian) (default: 42424242)
  -b BADCHARS [BADCHARS ...], --badchars BADCHARS [BADCHARS ...]
                        (required) List of known bad characters hexcode,
                        separated by space. eg. "00 01 04" (default: 00)
```

### BadChars Create

```
usage: roughbuff.py badchars-create [-h] -b BADCHARS [BADCHARS ...]

Create BadChar array

options:
  -h, --help            show this help message and exit
  -b BADCHARS [BADCHARS ...], --badchars BADCHARS [BADCHARS ...]
                        (required) List of known bad characters hexcode,
                        separated by space. eg. "00 01 04" (default: 00)
```

### Send Payload

```
usage: roughbuff.py payload-send [-h] -t TARGET -p PORT [-P PREFIX] [-c CHAR]
                                 [-T TIMEOUT] [-f POSTFIX] -o OFFSET [-e EIP]
                                 -x PAYLOAD [-n PADDING]

Exploit buffer overflow and send payload

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        (required) Target IP address or hostname
  -p PORT, --port PORT  (required) Target port
  -P PREFIX, --prefix PREFIX
                        Buffer prefix
  -c CHAR, --char CHAR  Buffer character (default: A)
  -T TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds (default: 5)
  -f POSTFIX, --postfix POSTFIX
                        Postfix string
  -o OFFSET, --offset OFFSET
                        (required) Buffer size required to rewrite EIP in
                        bytes
  -e EIP, --eip EIP     EIP in hex (big endian) (default: 42424242)
  -x PAYLOAD, --payload PAYLOAD
                        (required) Path to raw payload file eg. created by
                        msfvenom -f raw
  -n PADDING, --padding PADDING
                        Size of nop sled in bytes (default 16)
```
