config = {
    "ios":{
        "modulename": "Flutter",
        "patterns":{
            "arm64": [
                # First pattern is actually for macos
                "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F4 03 00 AA 68 31 00 F0 08 01 40 F9 08 01 40 F9 E8 07 00 F9",
                "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F9 ?8 1? 40 F9 15 ?? 4? F9 B5 00 00 B4",
                "FF 43 01 D1 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91 F3 03 00 AA 14 00 40 F9 88 1A 40 F9 15 E9 40 F9 B5 00 00 B4 B6 46 40 F9"

            ],
        },
    },
    "android":{
        "modulename": "libflutter.so",
        "patterns":{
            "arm64": [
                "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
                "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
                "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
            ],
            "arm": [
                "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8",
            ],
            "x64": [
                "55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B",
                "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
                "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB"
            ],
            "x86":[
                "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01"
            ]

        }
    },
    "windows": {
        "modulename": "flutter_windows.dll",
        "patterns":{
            "x64":[
                "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 4? 89 CF 48 8B 05 ?? ?? ?? 00 48 31 E0 48 89 44 24 38 4? 8B 31 4? 8B",
                "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 38 48 89 CF 48 8B 05 20 45 C6 00 48 31 E0 48 89 44 24 30 48 8B 31 48",
            ]
        }
    }

};
import os, glob, re, binascii, argparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

import re

def process_hex_pair(pair: str) -> bytes:
    """
    Convert a two-character hex pair that may contain wildcards to a regex pattern in bytes.
    
    - "??" is translated to b'.' (any byte).
    - A pair without wildcards is converted to its literal byte.
    - A pair with a single "?" (e.g., "1?" or "?F") creates a regex character class
      matching any allowed byte for that nibble.
    """
    if pair == "??":
        return b'.'
    elif '?' not in pair:
        try:
            byte_val = int(pair, 16)
        except ValueError:
            raise ValueError(f"Invalid hex pair: {pair}")
        # Convert the literal byte into a regex-safe form.
        return re.escape(bytes([byte_val]))
    else:
        if len(pair) != 2:
            raise ValueError("Each hex pair must have exactly two characters.")
        
        # Determine allowed values for the high nibble.
        if pair[0] == '?':
            high_nibbles = list(range(16))
        else:
            try:
                high_nibble = int(pair[0], 16)
            except ValueError:
                raise ValueError(f"Invalid hex digit: {pair[0]}")
            high_nibbles = [high_nibble]
        
        # Determine allowed values for the low nibble.
        if pair[1] == '?':
            low_nibbles = list(range(16))
        else:
            try:
                low_nibble = int(pair[1], 16)
            except ValueError:
                raise ValueError(f"Invalid hex digit: {pair[1]}")
            low_nibbles = [low_nibble]
        
        # Compute all allowed byte values for this pair.
        allowed = sorted({(h << 4) | l for h in high_nibbles for l in low_nibbles})
        
        # If the allowed bytes form a contiguous block, we can use a range.
        if allowed[-1] - allowed[0] == len(allowed) - 1:
            return b'[' + re.escape(bytes([allowed[0]])) + b'-' + re.escape(bytes([allowed[-1]])) + b']'
        else:
            # Otherwise, list them explicitly in a character class.
            return b'[' + b''.join(re.escape(bytes([val])) for val in allowed) + b']'

def hex_pattern_to_regex(hex_pattern: str) -> bytes:
    """
    Convert a hex string (with wildcards) to a regex pattern in bytes.
    
    Acceptable wildcards:
      - "??" matches any byte.
      - A single "?" in a hex pair (e.g., "1?" or "?F") matches any nibble in that position.
      
    Spaces in the input are ignored.
    """
    # Remove spaces and ensure even number of characters.
    hex_pattern = hex_pattern.replace(" ", "")
    if len(hex_pattern) % 2 != 0:
        raise ValueError("Hex pattern length must be even (each byte consists of two hex digits).")
    
    pattern_parts = []
    for i in range(0, len(hex_pattern), 2):
        pair = hex_pattern[i:i+2]
        pattern_parts.append(process_hex_pair(pair))
    return b''.join(pattern_parts)

def find_all_hex_pattern_offsets(filename: str, hex_pattern: str) -> list:
    """
    Search for the hex pattern (with wildcards) in the given binary file.
    
    Returns a list of offsets (indices) where the pattern is found.
    """
    regex_bytes = hex_pattern_to_regex(hex_pattern)
    # Compile the regex with DOTALL so that '.' matches any byte.
    pattern = re.compile(regex_bytes, re.DOTALL)
    
    with open(filename, "rb") as f:
        data = f.read()
    
    # Use finditer to locate all matches.
    return [match.start() for match in pattern.finditer(data)]


def scanFiles(apk=None):

    if apk:
        # files = list(glob.glob(folder + '/**', recursive=True))
        files = [
            f for lib_dir in glob.glob(os.path.join(apk, '**/lib'), recursive=True)
            for f in glob.glob(os.path.join(lib_dir, '**'), recursive=True)
            if os.path.isfile(f) and 'flutter' in os.path.basename(f).lower()
        ]
    else:
        files = list(glob.glob('./*/*/*'))                                      

    for file in files:                                    
        with open(file, mode='rb') as f:
            data = f.read()

        if "windows" in file:
            patterns = config["windows"]["patterns"]["x64"]
        elif "ios" in file or "macos" in file:
            patterns = config["ios"]["patterns"]["arm64"]
        elif "x64" in file or "x86_64" in file:
            patterns = config["android"]["patterns"]["x64"]
        elif "arm64" in file or "arm64-v8a" in file:
            patterns = config["android"]["patterns"]["arm64"]
        elif "arm" in file or "armeabi-v7a" in file:
            patterns = config["android"]["patterns"]["arm"]
        elif "x86" in file:
            patterns = config["android"]["patterns"]["x86"]

        results = []
        for hex_pattern in patterns:
            offsets = find_all_hex_pattern_offsets(file, hex_pattern)
            results += [(hex(a), hex_pattern) for a in offsets]
            
        if len(results) == 1:
            location = results[0][0]
            print(f"{file} > {bcolors.OKGREEN} OK {bcolors.ENDC} [{location}] [{results[0][1]}]")
        elif len(results) > 1:
                print(f"{file} > {bcolors.FAIL} {len(results)} results {bcolors.ENDC}")  
        else:
            print(f"{file} > {bcolors.FAIL} NOK {bcolors.ENDC}")





if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify hashes against samples or given APK folder")
    parser.add_argument('-a', '--apk', default=None, help='If given, scans APK folder for libflutter.so')
    args = parser.parse_args()

    scanFiles(args.apk)
