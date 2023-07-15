# RPECLI

Rust blazing fast alternative to [pecli](https://github.com/Te-k/pecli). `pecli` is a great tool, but it uses pefile, which is a bit slow to load PE executables, especialy when dealing with a whole lot of executables. This project aims at being a faster alternative to pecli.

This project currently relies on the [`exe`](https://crates.io/crates/exe) create, that was created with malware parsing in mind.


## Usage
```
Rust cli tool to parse PE files

Usage: rpecli.exe [OPTIONS] <COMMAND>

Commands:
  info           Print all available information
  import-export  Print both import and exports
  import         Print imports
  export         Print exports
  rsrc           Print resources
  sig            Print authenticode signature
  help           Print this message or the help of the given subcommand(s)

Options:
  -n, --no-hash  Do not compute hash of PE file. (This should greatly improve performance)
  -h, --help     Print help
  -V, --version  Print version
```

```
.\rpecli AcXtrnal.dll

Metadata:
================================================================================
MD5       : b5a919d087781aae652058362e6e44df
SHA1      : 4418bb0218edb25bddea234bec5ead0d02025cd7
SHA256    : 0a6339ed614079868ae9984bd688bfa9f0c8a585a8af7dcfe1866954cd780475

Size:           36 KiB (36864 bytes)
Type:           X64 DLL
Compile Time:   2026-05-28 17:06:18 (Timestamp: 1779987978 (0x6a18760a))
Subsystem:      WindowsCUI
Entrypoint:     0x12b0 => .text

Code at entrypoint:
================================================================================
48895C2408           mov [rsp+8],rbx
4889742410           mov [rsp+10h],rsi
57                   push rdi
4883EC20             sub rsp,20h
498BF8               mov rdi,r8
8BDA                 mov ebx,edx
488BF1               mov rsi,rcx
83FA01               cmp edx,1
7505                 jne short 0000000000000021h
E883050000           call 00000000000005A4h

Signature:
================================================================================
PE file is not signed


Rich headers:
================================================================================

  Product Name      Build   Product ID   Count   Guessed Visual Studio version
  Implib900         30729   147          2       Visual Studio 2008 09.00
  Utc1900_CPP       29395   261          2       Visual Studio 2015 14.00
  Utc1900_C         29395   260          12      Visual Studio 2015 14.00
  Masm1400          29395   259          3       Visual Studio 2015 14.00
  Implib1400        29395   257          9       Visual Studio 2015 14.00
  Import0           0       1            123     Visual Studio
  Export1400        29395   256          1       Visual Studio 2015 14.00
  Utc1900_LTCG_C    29395   264          9       Visual Studio 2017 14.01+
  Cvtres1400        29395   255          1       Visual Studio 2015 14.00
  Linker1400        29395   258          1       Visual Studio 2015 14.00



Sections:
================================================================================

    Name    VirtAddr   VirtSize   RawAddr   RawSize   Entropy                  md5                                         Characteristics
  .text       0x1000     0x1a59    0x1000    0x2000      5.23    f1012214f818509b5ffb52d85f8f7a73   60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)
  .rdata      0x3000     0x124e    0x3000    0x2000      2.99    3021728546e74dd5ebe73962c3100b0a   40000040 (CNT_INITIALIZED_DATA | MEM_READ)
  .data       0x5000      0x780    0x5000    0x1000      0.13    9b1a49ef1aae34f4cb7ae70537b38d0f   C0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
  .pdata      0x6000      0x1a4    0x6000    0x1000      0.57    6267372c124e5255059bff73416a072a   40000040 (CNT_INITIALIZED_DATA | MEM_READ)
  .rsrc       0x7000      0x408    0x7000    0x1000      1.10    6b3fa71c38edf3c403b297b77f8a4886   40000040 (CNT_INITIALIZED_DATA | MEM_READ)
  .reloc      0x8000       0x38    0x8000    0x1000      0.13    9a436d4b3782f8b0393438a2693060a2   42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)




Imports:
================================================================================

apphelp.dll
        SE_ShimDPF
        SE_GetShimId

msvcrt.dll
        _initterm
        malloc
        free
        _amsg_exit
        _XcptFilter
        memset
        __C_specific_handler
        _wcsicmp
        memcpy

ntdll.dll
        RtlVirtualUnwind
        RtlLookupFunctionEntry
        RtlCaptureContext
        RtlInitializeCriticalSection
        RtlLeaveCriticalSection
        RtlEnterCriticalSection
        LdrUnlockLoaderLock
        LdrFindEntryForAddress
        LdrLockLoaderLock
        NtQueryInformationThread
        RtlAllocateHeap

kernel32.dll
        TerminateProcess
        CreateEventW
        Sleep
        SetEvent
        Thread32Next
        CloseHandle
        QueueUserAPC
        OpenThread
        GetCurrentThreadId
        Thread32First
        GetCurrentProcessId
        CreateToolhelp32Snapshot
        GetModuleHandleW
        WaitForSingleObject
        UnhandledExceptionFilter
        SetUnhandledExceptionFilter
        GetTickCount
        GetSystemTimeAsFileTime
        QueryPerformanceCounter
        GetCurrentProcess

api-ms-win-eventing-provider-l1-1-0.dll
        EventWriteTransfer

imphash: 1062d7530750e6553052fe265d51f3f3

Exports:
================================================================================

"AcXtrnal.dll" => 2 exported function(s)
          1 GetHookAPIs
          2 NotifyShims 

exphash: 53ca8c9718c7d2697bcf11c01c7f3116
Export timestamp: 2026-05-28 17:06:18 (Timestamp: 1779987978 (0x6a18760a))

Debug info:
================================================================================
Entry 0:
  Type      : Codeview
  Timestamp : 2026-05-28 17:06:18 (Timestamp: 1779987978 (0x6a18760a))

  CodeView (v70)
    Signature      : {39C0C7D0-4750-A208-7B86-2186555012A3}
    Age            : 1
    PDB filename   : "AcXtrnal.pdb"

Entry 1:
  Type      : Pogo
  Timestamp : 2026-05-28 17:06:18 (Timestamp: 1779987978 (0x6a18760a))

  PGO:
    0x001000 ".text$mn" (size : 0x16d0)
    0x0026d0 ".text$mn$00" (size : 0x40)
    0x002710 ".text$x" (size : 0x349)
    0x003000 ".rdata$brc" (size : 0x148)
    0x003148 ".idata$5" (size : 0x180)
    0x0032c8 ".00cfg" (size : 0x28)
    0x0032f0 ".CRT$XCA" (size : 0x8)
    0x0032f8 ".CRT$XCZ" (size : 0x8)
    0x003300 ".CRT$XIA" (size : 0x8)
    0x003308 ".CRT$XIAA" (size : 0x8)
    0x003310 ".CRT$XIZ" (size : 0x8)
    0x003318 ".gehcont" (size : 0x30)
    0x003348 ".gfids" (size : 0x38)
    0x003380 ".rdata" (size : 0x488)
    0x003808 ".rdata$zzzdbg" (size : 0x250)
    0x003a58 ".xdata" (size : 0x208)
    0x003c60 ".edata" (size : 0x64)
    0x003cc4 ".idata$2" (size : 0x64)
    0x003d28 ".idata$3" (size : 0x18)
    0x003d40 ".idata$4" (size : 0x180)
    0x003ec0 ".idata$6" (size : 0x38e)
    0x005000 ".data$brc" (size : 0x50)
    0x005050 ".data" (size : 0x30)
    0x005080 ".bss" (size : 0x700)
    0x006000 ".pdata" (size : 0x1a4)
    0x007000 ".rsrc$01" (size : 0x60)
    0x007060 ".rsrc$02" (size : 0x3a8)

Entry 2:
  Type      : Repro
  Timestamp : 2026-05-28 17:06:18 (Timestamp: 1779987978 (0x6a18760a))

  Entry of type Repro is not supported for display

Entry 3:
  Type      : ExDllCharacteristics
  Timestamp : 2026-05-28 17:06:18 (Timestamp: 1779987978 (0x6a18760a))

  Entry of type ExDllCharacteristics is not supported for display


Resources:
================================================================================

    Name     Offset   RSRC ID    Lang ID                   MD5

  Version      48      ID(1)     ID(1033)    0ea64388fb73ef52be989c95368b971e



TLS callbacks:
================================================================================
No TLS callback directory
```

## Build
```
cargo build --release
```

## Install
```
cargo install rpecli
```
or locally :
```
cargo install --path .
```

## TODO
- Refacto of some parts
- Error handling
- Possiblity to dump resources
- Feature to handle comparing some fields between multiple binaries to help finding header similarities
