# RPECLI

Rust blazing fast cross-platform and hopefully accurate alternative to [pecli](https://github.com/Te-k/pecli). `pecli` is a great tool, but it uses pefile, which is a bit slow to load PE executables, especialy when dealing with a whole lot of executables.

This project currently relies on the [`exe`](https://crates.io/crates/exe) create, that was created with malware parsing in mind.

It also exports its parsed data through a lib you can use in your own projects.
Some command can also output their result as a JSON string for you to parse.

## Usage
```
Rust cli tool to parse PE files


This tool is still under development.
Some of the commands have a `--json` argument that outputs the result as a JSON string.
Try "rpecli COMMAND --help" to show help for a specific command.
Certain commands support multiple PE files as arguments and will compare them if you give multiple PE files.

Usage: rpecli [OPTIONS] <COMMAND>

Commands:
  info           Print all available information
  import-export  Print both import and exports
  import         Print imports
  export         Print exports
  rich           Rich headers
  rsrc           Print or dump resources
  sig            Print authenticode signature
  disass         Disassemble section
  strings        Print strings
  test           Test command for development
  help           Print this message or the help of the given subcommand(s)

Options:
  -n, --no-hash  Do not compute any hashes when reading PE file. (Enabling this option should greatly improve performance)
  -h, --help     Print help
  -V, --version  Print version
```

```
.\rpecli kernel32.dll

Metadata:
================================================================================
MD5       : e44c6872f7e2dade42e472b2c062c7b0
SHA1      : cc2fcdf6b747943c196d49f7ed55d308d7ef4d9b
SHA256    : 03bf2226a8cf553fd2a0f22a9f27c3f0f0ec3e99aa061f7219821caa4142c175

Size:           772.1 KiB (790616 bytes)
Type:           X64 DLL
Compile Time:   2066-08-28 19:59:40 (Timestamp: 3050251180 (0xb5cf23ac))
Subsystem:      WindowsCUI
Entrypoint:     0x15640 => .text

Code at entrypoint:
================================================================================
48895C2408           mov [rsp+8],rbx
57                   push rdi
4883EC20             sub rsp,20h
8BFA                 mov edi,edx
488BD9               mov rbx,rcx
BA01000000           mov edx,1
3BFA                 cmp edi,edx
7505                 jne short 000000000000001Dh
E817D80000           call 000000000000D834h
8BD7                 mov edx,edi

Signature:
================================================================================
Signature 0:
  Signature digest: 852fb691ec19bd403547973f1a963fc17fee2376c25a2590427de1705bc8cfec

  Signer:
    Issuer:        C=US,STATEORPROVINCENAME=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Windows Production PCA 2011
    Serial number: 33:00:00:04:0C:12:00:67:8B:16:B2:65:DB:00:00:00:00:04:0C
  Certificate 0:
    Issuer:        C=US,STATEORPROVINCENAME=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Windows Production PCA 2011
    Subject:       C=US,STATEORPROVINCENAME=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Windows
    Serial number: 33:00:00:04:0C:12:00:67:8B:16:B2:65:DB:00:00:00:00:04:0C
  Certificate 1:
    Issuer:        C=US,STATEORPROVINCENAME=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2010
    Subject:       C=US,STATEORPROVINCENAME=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Windows Production PCA 2011
    Serial number: 61:07:76:56:00:00:00:00:00:08



Rich headers:
================================================================================

  Product Name       Build   Product ID   Count   Guessed Visual Studio version
  Implib1400         29395   257          4       Visual Studio 2015 14.00
  Implib900          30729   147          201     Visual Studio 2008 09.00
  Import0            0       1            1332    Visual Studio
  Utc1900_C          29395   260          10      Visual Studio 2015 14.00
  Export1400         29395   256          1       Visual Studio 2015 14.00
  Masm1400           29395   259          5       Visual Studio 2015 14.00
  Utc1900_POGO_O_C   29395   269          207     UNKN
  Cvtres1400         29395   255          1       Visual Studio 2015 14.00
  Linker1400         29395   258          1       Visual Studio 2015 14.00



Sections:
================================================================================

    Name    VirtAddr   VirtSize   RawAddr   RawSize   Entropy                  md5                                         Characteristics
  .text       0x1000    0x7de27    0x1000   0x7e000      6.39    e64217696a3b17b4d623e585246a0d66   60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)
  .rdata     0x7f000    0x337b4   0x7f000   0x34000      5.62    78058c4b075118a4e2f44f428859761a   40000040 (CNT_INITIALIZED_DATA | MEM_READ)
  .data      0xb3000     0x12e4   0xb3000    0x1000      1.17    55b8682f534b352b31d73ad57bbcef5d   C0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
  .pdata     0xb5000     0x5544   0xb4000    0x6000      5.43    91c69814336303f6adff1de3999a993f   40000040 (CNT_INITIALIZED_DATA | MEM_READ)
  .didat     0xbb000       0xa8   0xba000    0x1000      0.23    302f288de68cff124618438bb2d632cf   C0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
  .rsrc      0xbc000      0x520   0xbb000    0x1000      1.32    d58796bd5bf9664ed21be9166aab39fd   40000040 (CNT_INITIALIZED_DATA | MEM_READ)
  .reloc     0xbd000      0x348   0xbc000    0x1000      1.74    82affef2f6f4f8f22ad4f220b1b7a7c6   42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)


Imports:
================================================================================

api-ms-win-core-rtlsupport-l1-1-0.dll
        RtlCompareMemory
        RtlDeleteFunctionTable
[SNIP]

api-ms-win-core-appcompat-l1-1-1.dll
        BaseReadAppCompatDataForProcess
        BaseFreeAppCompatDataForProcess

imphash: 5529a33510d7fd9c2cfa748e0d102653

Exports:
================================================================================

"KERNEL32.dll" => 1657 exported function(s)
          1 AcquireSRWLockExclusive (Forwarded export)
[SNIP]
         1657 uaw_wcsrchr

exphash: 4ca79cdc84d990b7803d389563eba24a
Export timestamp: 2066-08-28 19:59:40 (Timestamp: 3050251180 (0xb5cf23ac))

Debug info:
================================================================================
Entry 1:
  Type      : Codeview
  Timestamp : 2066-08-28 19:59:40 (Timestamp: 3050251180 (0xb5cf23ac))

  CodeView (v70)
    Signature      : {12950B30-DA44-7427-C06E-E816EFA3EBC6}
    Age            : 1
    PDB filename   : "kernel32.pdb"

Entry 2:
  Type      : Pogo
  Timestamp : 2066-08-28 19:59:40 (Timestamp: 3050251180 (0xb5cf23ac))

  PGO:
    0x001000 ".text$lp00kernel32.dll!20_pri7" (size : 0xb10)
    0x001b10 ".text$lp01kernel32.dll!20_pri7" (size : 0x1f040)
[SNIP]
    0x0bc000 ".rsrc$01" (size : 0xb0)
    0x0bc0b0 ".rsrc$02" (size : 0x470)

Entry 3:
  Type      : Repro
  Timestamp : 2066-08-28 19:59:40 (Timestamp: 3050251180 (0xb5cf23ac))

  Entry of type Repro is not supported for display

Entry 4:
  Type      : ExDllCharacteristics
  Timestamp : 2066-08-28 19:59:40 (Timestamp: 3050251180 (0xb5cf23ac))

  Entry of type ExDllCharacteristics is not supported for display


Resources:
================================================================================

    Name     Offset   RSRC ID    Lang ID                   MD5

    MUI        80      ID(1)     ID(1033)    fbaf48ec981a5eecdb57b929fdd426e8

  Version      90      ID(1)     ID(1033)    3a1682660ad485730c4987c23ab5fdd7



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

## Internals

When creating this tool, speed and modularity was key considerations. It aims at providing interfaces that allow users to modify the PE parsing backend according to their needs. The default backend is the `exe` crate, specifically designed for parsing PE malwares.

Please note that the traits allowing backend customization are not yet available.


## Thanks
This project uses code from the following projects :
- [authenticode](https://crates.io/crates/authenticode)
- [pelite](https://crates.io/crates/pelite)
- [exe](https://crates.io/crates/exe)


## Issues

`54476b502ccd2c35f7c1642c20480e65310d51fc3e46abd01870c9bda5f5797e` is known not break exports.
