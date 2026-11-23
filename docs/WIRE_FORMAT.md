# VeraCrypt IPC Wire Format

VeraCrypt's `CoreService` IPC uses a custom binary serialization implemented in
`src/Platform/Serializer.cpp`. Understanding this format is required to craft
valid requests. This reference describes the protocol used by the included
live-session PoC on little-endian Linux; it is not a version-independent API.

---

## 1. Scalar Encoding: `Serialize<T>(T data)`

Every scalar value is prefixed by the **size of its type** (as a big-endian `uint64`),
followed by the **value itself** (also big-endian).

```
Serialize<T>(v)  →  [BE64: sizeof(T)]  [BE(sizeof(T)): v]
```

| Type | Wire bytes | Example value `42` |
|------|-----------|-------------------|
| `uint8`  | 9 bytes  | `00 00 00 00 00 00 00 01`  `2a` |
| `uint32` | 12 bytes | `00 00 00 00 00 00 00 04`  `00 00 00 2a` |
| `uint64` | 16 bytes | `00 00 00 00 00 00 00 08`  `00 00 00 00 00 00 00 2a` |
| `bool`   | 9 bytes  | encoded as `uint8`, value 0 or 1 |

---

## 2. Strings: `SerializeString(s)`

String data is encoded as a serialized `uint64` byte count (including the NUL)
followed by the raw string bytes and NUL terminator.

```
string "foo"  →  [00 00 00 00 00 00 00 08]   <- sizeof(uint64) = 8
                 [00 00 00 00 00 00 00 04]   <- len+1 = 4
                 [66 6f 6f 00]               <- "foo\0"
Total: 20 bytes
```

**Empty string** `""` → `[BE8 8][BE8 1][00]` = 17 bytes

---

## 3. Wide Strings: `SerializeWString(s)`

Wide-string data is encoded as a serialized `uint64` byte count, followed by
`(character_count + 1) * sizeof(wchar_t)` raw bytes including the terminator.

On the reproduced little-endian Linux systems, `sizeof(wchar_t) == 4` and
the raw wide-string data is UTF-32LE. Scalar values and lengths are big-endian;
wide-string bytes remain in native order. The included encoder is not portable
to a big-endian host without changes. An empty wide string occupies 20 bytes:
16 bytes of length encoding followed by a four-byte NUL character.

```
wstring L"/dev/sdb"  (8 chars + NUL = 9 wchar_t = 36 bytes)
  →  [00 00 00 00 00 00 00 08]     <- sizeof(uint64) = 8
     [00 00 00 00 00 00 00 24]     <- bytecount = 36
     [2f 00 00 00]  '/'            <- UTF-32LE
     [64 00 00 00]  'd'
     [65 00 00 00]  'e'
     [76 00 00 00]  'v'
     [2f 00 00 00]  '/'
     [73 00 00 00]  's'
     [64 00 00 00]  'd'
     [62 00 00 00]  'b'
     [00 00 00 00]  NUL terminator
Total: 16 + 36 = 52 bytes
```

---

## 4. Named Fields

Every field is written as: `[field_name as string][value bytes]`. Field names
are narrow strings even when the corresponding value is a wide string.

```
Serialize("AdminPassword", "")
  →  [string "AdminPassword"]  [string ""]
  =  [BE8 8][BE8 14]["AdminPassword\0"]  [BE8 8][BE8 1]["\0"]
```

---

## 5. Serializable Objects

Every serializable class writes its class name first via `Serializable::Serialize()`:

```cpp
void Serializable::Serialize(shared_ptr<Stream> stream) const {
    Serializer sr(stream);
    sr.Serialize("SerializableName", GetSerializableName());
}
```

So every object on the wire starts with the field `"SerializableName"` containing
the class name as a string.

---

## 6. `SetFileOwnerRequest` Full Layout

Field order from `CoreServiceRequest::Serialize()` → `SetFileOwnerRequest::Serialize()`:

```
[string "SerializableName"]  = [string "SetFileOwnerRequest"]
[string "AdminPassword"]     = [string ""]
[string "ApplicationExecutablePath"] = [wstring L""]
[string "ElevateUserPrivileges"]      = [bool false]   ← set false when already elevated
[string "FastElevation"]              = [bool false]
[string "UserEnvPATH"]                = [string ""]
[string "UseDummySudoPassword"]       = [bool false]
[string "AllowInsecureMount"]         = [bool false]
[string "Owner"]             = [uint64 <uid>]
[string "Path"]             = [wstring L"<target_path>"]
```

---

## 7. IPC Session Structure

```
[3-byte sync: 0x00 0x11 0x22]          ← handshake for ProcessElevatedRequests()
[SetFileOwnerRequest packet 1]          ← loop: ProcessRequests() reads until EOF
[SetFileOwnerRequest packet 2]          ← multiple requests in one session
[ExitRequest packet]                    ← graceful shutdown
[close pipe]                            ← CoreService exits
```

The sequence above describes startup of a new elevated service. After the sync,
`ProcessRequests()` reads and dispatches requests until shutdown or an error.

The included live-session PoC targets a service that has already completed this
handshake. It writes only the `SetFileOwnerRequest` packets; it does **not** send
the sync bytes or an `ExitRequest` into the active session.

---

## 8. `ExitRequest` Layout

`ExitRequest` has no extra fields beyond the base `CoreServiceRequest`:

```
[string "SerializableName"]  = [string "ExitRequest"]
[string "AdminPassword"]     = [string ""]
[string "ApplicationExecutablePath"] = [wstring L""]
[string "ElevateUserPrivileges"]      = [bool false]
[string "FastElevation"]              = [bool false]
[string "UserEnvPATH"]                = [string ""]
[string "UseDummySudoPassword"]       = [bool false]
[string "AllowInsecureMount"]         = [bool false]
```

---

## 9. C Encoding Reference

```c
/* [BE8 8][BE8 value] — 16 bytes */
static size_t wr_u64(uint8_t *b, uint64_t v) {
    put_be64(b, 8); put_be64(b+8, v); return 16;
}

/* [BE8 1][value] — 9 bytes */
static size_t wr_u8(uint8_t *b, uint8_t v) {
    put_be64(b, 1); b[8] = v; return 9;
}

/* [BE8 8][BE8 len+1][data+NUL] */
static size_t wr_str(uint8_t *b, const char *s) {
    size_t len = strlen(s) + 1;
    put_be64(b, 8); put_be64(b+8, len); memcpy(b+16, s, len);
    return 16 + len;
}

/* [BE8 8][BE8 (len+1)*4][UTF-32LE data] */
static size_t wr_wstr(uint8_t *b, const char *s) {
    size_t slen = strlen(s);
    uint64_t wsz = (slen + 1) * 4;
    put_be64(b, 8); put_be64(b+8, wsz);
    for (size_t i = 0; i <= slen; i++) {
        b[16+i*4]=s[i]; b[16+i*4+1]=0; b[16+i*4+2]=0; b[16+i*4+3]=0;
    }
    return 16 + wsz;
}
```
