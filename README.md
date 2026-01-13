# UxPlay Heap Buffer Overflow in HTTP Response Construction (CWE-122)

## Summary

A **heap-based buffer overflow (WRITE)** vulnerability exists in **UxPlay v1.73** within the HTTP/RTSP response construction logic.  
The flaw is caused by incorrect buffer growth conditions in `http_response_add_data()`, resulting in a deterministic heap write overflow during normal, unauthenticated request handling.

- **Component:** HTTP response construction  
- **File:** `lib/http_response.c`  
- **Function:** `http_response_add_data()`  
- **UxPlay Version:** 1.73  
- **Bug Type:** Heap buffer overflow (WRITE)  
- **CWE:** CWE-122 (Heap-Based Buffer Overflow)

---

## Overview

While constructing HTTP/RTSP responses, UxPlay incrementally appends header fragments into a heap buffer.  
Due to a logic error in the buffer resizing condition, the function may perform a `memcpy()` write **past the end of the allocated heap buffer**.

The issue is **deterministic under AddressSanitizer**, occurs during **normal protocol handling**, and does **not require authentication**.

---

## Call Path

```
httpd_thread
 └─ conn_request
     └─ http_response_add_header
         └─ http_response_add_data   <-- heap overflow
```

The overflow occurs while building server responses (headers and body).

---

## AddressSanitizer

```c
➜  build_asan git:(master) ✗ ./uxplay -vs 0 -as 0 -p 7000
UxPlay 1.73: An Open-Source AirPlay mirroring and audio-streaming server.
video_disabled
audio_disabled
using network ports UDP 7000 7001 7002 TCP 7000 7001 7002
using system MAC address 00:15:5d:f3:17:fd
Initialized server socket(s)
Accepted IPv4 client on socket 18, port 7001
Local : 127.0.0.1
Remote: 127.0.0.1
=================================================================
==1814==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x51d00001dd24 at pc 0x649276748718 bp 0x761fd4ffe870 sp 0x761fd4ffe868
WRITE of size 2 at 0x51d00001dd24 thread T1
    #0 0x649276748717 in http_response_add_data /home/grover/research/uxplay_fuzzer/uxplay_src/lib/http_response.c:48:5
    #1 0x649276748717 in http_response_add_header /home/grover/research/uxplay_fuzzer/uxplay_src/lib/http_response.c:126:5
    #2 0x64927672aa93 in conn_request /home/grover/research/uxplay_fuzzer/uxplay_src/lib/raop.c:457:13
    #3 0x64927674bbef in httpd_thread /home/grover/research/uxplay_fuzzer/uxplay_src/lib/httpd.c:559:17
    #4 0x6492766baf3a in asan_thread_start(void*) asan_interceptors.cpp.o
    #5 0x761fd85acb7a in start_thread nptl/pthread_create.c:448:8
    #6 0x761fd862a7b7 in __GI___clone3 misc/../sysdeps/unix/sysv/linux/x86_64/clone3.S:78

0x51d00001dd24 is located 2212 bytes after 2048-byte region [0x51d00001cc80,0x51d00001d480)
allocated by thread T1 here:
    #0 0x6492766bda00 in realloc (/home/grover/research/uxplay_fuzzer/uxplay_src/build_asan/uxplay+0xf9a00) (BuildId: 9e965e6fcd78cba62e75868729d68cb90cb66ea6)
    #1 0x6492767484c6 in http_response_add_data /home/grover/research/uxplay_fuzzer/uxplay_src/lib/http_response.c:45:26
    #2 0x6492767484c6 in http_response_add_header /home/grover/research/uxplay_fuzzer/uxplay_src/lib/http_response.c:126:5
    #3 0x64927672aa93 in conn_request /home/grover/research/uxplay_fuzzer/uxplay_src/lib/raop.c:457:13
    #4 0x64927674bbef in httpd_thread /home/grover/research/uxplay_fuzzer/uxplay_src/lib/httpd.c:559:17
    #5 0x6492766baf3a in asan_thread_start(void*) asan_interceptors.cpp.o

Thread T1 created by T0 here:
    #0 0x6492766a2ea5 in pthread_create (/home/grover/research/uxplay_fuzzer/uxplay_src/build_asan/uxplay+0xdeea5) (BuildId: 9e965e6fcd78cba62e75868729d68cb90cb66ea6)
    #1 0x64927674a83c in httpd_start /home/grover/research/uxplay_fuzzer/uxplay_src/lib/httpd.c:675:5
    #2 0x64927670c179 in start_raop_server(unsigned short*, unsigned short*, unsigned short*, bool) /home/grover/research/uxplay_fuzzer/uxplay_src/uxplay.cpp:2645:5
    #3 0x64927670c179 in main /home/grover/research/uxplay_fuzzer/uxplay_src/uxplay.cpp:3079:9
    #4 0x761fd8543ca7 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/grover/research/uxplay_fuzzer/uxplay_src/lib/http_response.c:48:5 in http_response_add_data
Shadow bytes around the buggy address:
  0x51d00001da80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001db00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001db80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001dc00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001dc80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x51d00001dd00: fa fa fa fa[fa]fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001dd80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001de00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001de80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001df00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x51d00001df80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==1814==ABORTING
```

### Info

- **Allocated buffer size:** 2048 bytes  
- **Write offset:** 2212 bytes beyond the allocated region  
- **Operation:** `memcpy()`  
- **Behavior:** Deterministic crash under ASAN  

This confirms a **real heap write overflow**, not a false positive.

---

## Vulnerable code

From `lib/http_response.c`:

```c
static void
http_response_add_data(http_response_t *response, const char *data, int datalen)
{
    int newdatasize = response->data_size;
    while (response->data_size + datalen > newdatasize) {
        newdatasize *= 2;
    }
    if (newdatasize != response->data_size) {
        response->data = realloc(response->data, newdatasize);
        assert(response->data);
    }
    memcpy(response->data + response->data_length, data, datalen);
    response->data_length += datalen;
}
```

---

## Root Cause Analysis (RCA)

The buffer resize check is via

```c
while (response->data_size + datalen > newdatasize)
```

However, the actual write offset is:

```c
response->data + response->data_length
```

The code **completely ignores `response->data_length`**, which tracks how much of the buffer is already in use.

---

## Concrete

| Variable        | Value |
|-----------------|-------|
| `data_size`    | 2048  |
| `data_length`  | 2046  |
| `datalen`      | 2     |

**Check performed:**
```
2048 + 2 > 2048  → false
```

**Actual write:**
```
memcpy(response->data + 2046, data, 2)
```

This results in a write **past the end of the heap buffer**, causing a heap buffer overflow.

---

## Why This Is Reachable

- `http_response_add_data()` is invoked repeatedly during response construction
- Headers are appended incrementally

```
http_response_add_header()
  ├─ name
  ├─ ": "
  ├─ value
  ├─ "\r\n"
```

- `data_length` grows independently of `data_size`
- No guard or reset exists between calls
- The overflow can be triggered by response size alone (no malformed input required)

---

## Why ASAN Reports +2212 Bytes

AddressSanitizer reports:

```
2212 bytes after a 2048-byte region
```

This indicates:

- `data_length` had already exceeded `data_size`
- The reallocation logic failed to trigger
- `memcpy()` wrote far beyond the allocated heap chunk

This confirms **true heap memory corruption**.

---

## Impact

- Heap memory corruption
- Deterministic crash under AddressSanitizer
- Undefined behavior in production builds
- Network-reachable code path
- No authentication required
