# PE 文件格式的解析

## 一、环境
### 1.环境：
Windows + MingGW


### 2.环境变量：
```
C:\Program Files\mingw\mingw64\bin
```
这里替换成你的环境


## 二、编译运行
### 1.编译方法:
```
g++ -g -O0 .\main.cpp .\common.cpp .\pe.cpp .\show.cpp -o pe.exe -limagehlp
```
### 2.运行：
```
pe.exe pe.exe
```

## 三、文件结构
1. main.cpp 主程序
2. pe.h pe.cpp 定位 PE
3. show.h show.cpp 解析和现实 PE

## 四、已经解析的部分
### 1.DOS 头：
```
IMAGE_DOS_HEADER:
        e_magic:5a4d
        e_lfanew:80
```


### 2.NT 头：
```
IMAGE_NT_HEADERS
        000: Signature:4550
IMAGE_FILE_HEADER
        004: Machine: 8664
        006: NumberOfSections: 12
        008: TimeDateStamp: 692fb742      
        00c: PointerToSymbolTable: 51200  
        010: NumberOfSymbols: 9ae
        014: SizeOfOptionalHeader: f0     
        016: Characteristics: 26
IMAGE_OPTIONAL_HEADER
        018: Magic:20b
        01a: MajorLinkerVersion:2
        01b: MinorLinkerVersion:2d        
        01c: SizeOfCode:6e00
        020: SizeOfInitializedData:3c00   
        024: SizeOfUninitializedData:200  
        028: AddressOfEntryPoint:1046     
        02c: BaseOfCode:1000
        030: ImageBase:140000000
        038: SectionAlignment:1000        
        03c: FileAlignment:200
        040: MajorOperatingSystemVersion:4
        042: MinorOperatingSystemVersion:0
        044: MajorImageVersion:0
        046: MinorImageVersion:0
        048: MajorSubsystemVersion:5      
        04a: MinorSubsystemVersion:2
        04c: Win32VersionValue:0
        050: SizeOfImage:5c000
        054: SizeOfHeaders:600
        058: CheckSum:6f373
        05c: Subsystem:3
        05e: DllCharacteristics:160
        060: SizeOfStackReserve:200000
        068: SizeOfStackCommit:1000
        070: SizeOfHeapReserve:100000
        078: SizeOfHeapCommit:1000
        080: LoaderFlags:0
        084: NumberOfRvaAndSizes:10
```

### 3.节表：
```
IMAGE_SECTION_HEADER
        Name:.text
                VirtualSize:00006d50  VirtualAddress:00001000  SizeOfRawData:00006e00  PointerToRawData:00000600
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:60000020
        Name:.data
                VirtualSize:000000e0  VirtualAddress:00008000  SizeOfRawData:00000200  PointerToRawData:00007400
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:c0000040
        Name:.rdata
                VirtualSize:000017b0  VirtualAddress:00009000  SizeOfRawData:00001800  PointerToRawData:00007600
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:40000040
        Name:/4
                VirtualSize:00000004  VirtualAddress:0000b000  SizeOfRawData:00000200  PointerToRawData:00008e00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:c0000040
        Name:.pdata
                VirtualSize:000006c0  VirtualAddress:0000c000  SizeOfRawData:00000800  PointerToRawData:00009000
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:40000040
        Name:.xdata
                VirtualSize:00000724  VirtualAddress:0000d000  SizeOfRawData:00000800  PointerToRawData:00009800
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:40000040
        Name:.bss
                VirtualSize:000001a0  VirtualAddress:0000e000  SizeOfRawData:00000000  PointerToRawData:00000000
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:c0000080
        Name:.idata
                VirtualSize:00000b98  VirtualAddress:0000f000  SizeOfRawData:00000c00  PointerToRawData:0000a000
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:40000040
        Name:.tls
                VirtualSize:00000010  VirtualAddress:00010000  SizeOfRawData:00000200  PointerToRawData:0000ac00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:c0000040
        Name:.reloc
                VirtualSize:0000007c  VirtualAddress:00011000  SizeOfRawData:00000200  PointerToRawData:0000ae00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/14
                VirtualSize:00000aa0  VirtualAddress:00012000  SizeOfRawData:00000c00  PointerToRawData:0000b000
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/29
                VirtualSize:0003aa6e  VirtualAddress:00013000  SizeOfRawData:0003ac00  PointerToRawData:0000bc00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/41
                VirtualSize:000027a7  VirtualAddress:0004e000  SizeOfRawData:00002800  PointerToRawData:00046800
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/55
                VirtualSize:000038b9  VirtualAddress:00051000  SizeOfRawData:00003a00  PointerToRawData:00049000
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/67
                VirtualSize:000016c0  VirtualAddress:00055000  SizeOfRawData:00001800  PointerToRawData:0004ca00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/80
                VirtualSize:000015e5  VirtualAddress:00057000  SizeOfRawData:00001600  PointerToRawData:0004e200
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/91
                VirtualSize:00001109  VirtualAddress:00059000  SizeOfRawData:00001200  PointerToRawData:0004f800
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:/107
                VirtualSize:0000068d  VirtualAddress:0005b000  SizeOfRawData:00000800  PointerToRawData:00050a00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
```
处理节表中以 / 开头的节名称
```
        Name:(/14).debug_aranges
                VirtualSize:00001350  VirtualAddress:00017000  SizeOfRawData:00001400  PointerToRawData:00010e00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/29).debug_info
                VirtualSize:0005b96c  VirtualAddress:00019000  SizeOfRawData:0005ba00  PointerToRawData:00012200
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/41).debug_abbrev
                VirtualSize:00002f61  VirtualAddress:00075000  SizeOfRawData:00003000  PointerToRawData:0006dc00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/55).debug_line
                VirtualSize:00006198  VirtualAddress:00078000  SizeOfRawData:00006200  PointerToRawData:00070c00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/67).debug_frame
                VirtualSize:000039a8  VirtualAddress:0007f000  SizeOfRawData:00003a00  PointerToRawData:00076e00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/80).debug_str
                VirtualSize:00002157  VirtualAddress:00083000  SizeOfRawData:00002200  PointerToRawData:0007a800
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/91).debug_line_str
                VirtualSize:00001238  VirtualAddress:00086000  SizeOfRawData:00001400  PointerToRawData:0007ca00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
        Name:(/107).debug_rnglists
                VirtualSize:00000c7a  VirtualAddress:00088000  SizeOfRawData:00000e00  PointerToRawData:0007de00
                PointerToRelocations:00000000  PointerToLinenumbers:00000000  NumberOfRelocations:00000000  NumberOfLinenumbers:00000000
                Characteristics:42000040
```

### 4.数据目录：
```
IMAGE_DATA_DIRECTORY
        NumberOfRvaAndSizes:16
        IMAGE_DIRECTORY_ENTRY_EXPORT:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_IMPORT:00010000:00000b98
        IMAGE_DIRECTORY_ENTRY_RESOURCE:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_EXCEPTION:0000d000:000006cc
        IMAGE_DIRECTORY_ENTRY_SECURITY:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_BASERELOC:00012000:0000007c
        IMAGE_DIRECTORY_ENTRY_DEBUG:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_TLS:0000a940:00000028
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_IAT:000102b8:00000240
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:00000000:00000000
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:00000000:00000000
```


### 5.导入表：
```
IMAGE_IMPORT_DESCRIPTOR
        libgcc_s_seh-1.dll
                14 _Unwind_Resume
        libstdc++-6.dll
                1913 _ZNSolsEPFRSoS_E
                1914 _ZNSolsEPFRSt8ios_baseS0_E
                1922 _ZNSolsEi
                1924 _ZNSolsEl
                1925 _ZNSolsEm
                1927 _ZNSolsEt
                1928 _ZNSolsEx
                1929 _ZNSolsEy
                5535 _ZSt17__throw_bad_allocv
                5549 _ZSt19__throw_logic_errorPKc
                5558 _ZSt20__throw_length_errorPKc
                5566 _ZSt21__glibcxx_assert_failPKciS0_S0_
                5591 _ZSt4cout
                5592 _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
                5711 _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
                5712 _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKh
                5719 _ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_St5_Setw
                5721 _ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_St8_SetfillIS3_E
                6808 _ZdlPvy
                6814 _Znwy
                6860 __gxx_personality_seh0
        imagehlp.dll
                28 ImageRvaToSection
        KERNEL32.dll
                151 CloseHandle
                215 CreateFileA
                216 CreateFileMappingA
                295 DeleteCriticalSection
                333 EnterCriticalSection
                458 FreeLibrary
                648 GetLastError
                670 GetModuleHandleA
                730 GetProcAddress
                918 InitializeCriticalSection
                1012 LeaveCriticalSection
                1016 LoadLibraryA
                333 EnterCriticalSection
                458 FreeLibrary
                648 GetLastError
                670 GetModuleHandleA
                730 GetProcAddress
                918 InitializeCriticalSection
                1012 LeaveCriticalSection
                1016 LoadLibraryA
                458 FreeLibrary
                648 GetLastError
                670 GetModuleHandleA
                730 GetProcAddress
                918 InitializeCriticalSection
                1012 LeaveCriticalSection
                1016 LoadLibraryA
                670 GetModuleHandleA
                730 GetProcAddress
                918 InitializeCriticalSection
                1012 LeaveCriticalSection
                1016 LoadLibraryA
                1047 MapViewOfFile
                1433 SetUnhandledExceptionFilter
                1047 MapViewOfFile
                1433 SetUnhandledExceptionFilter
                1433 SetUnhandledExceptionFilter
                1449 Sleep
                1485 TlsGetValue
                1503 UnmapViewOfFile
                1533 VirtualProtect
                1535 VirtualQuery
                1588 WideCharToMultiByte
                1449 Sleep
                1485 TlsGetValue
                1503 UnmapViewOfFile
                1533 VirtualProtect
                1535 VirtualQuery
                1588 WideCharToMultiByte
        msvcrt.dll
                1485 TlsGetValue
                1503 UnmapViewOfFile
                1533 VirtualProtect
                1535 VirtualQuery
                1588 WideCharToMultiByte
        msvcrt.dll
                1533 VirtualProtect
                1535 VirtualQuery
                1588 WideCharToMultiByte
        msvcrt.dll
                1535 VirtualQuery
                1588 WideCharToMultiByte
        msvcrt.dll
                1588 WideCharToMultiByte
        msvcrt.dll
                89 __C_specific_handler
        msvcrt.dll
                89 __C_specific_handler
                89 __C_specific_handler
                127 __getmainargs
                128 __initenv
                129 __iob_func
                146 __set_app_type
                148 __setusermatherr
                181 _amsg_exit
                202 _cexit
                221 _commode
                322 _fmode
                414 _initterm
                1144 abort
                1156 atexit
                1163 calloc
                1177 exit
                1198 fprintf
                1205 free
                1270 malloc
                1279 memcpy
                1281 memset
                1312 signal
                1332 strlen
                1335 strncmp
                1373 vfprintf
```


### 6.重定位表

```
0:VirtualAddress:9000 SizeOfBlock:1c Number:a
        a:00009010
        a:00009070
        a:00009080
        a:00009090
        a:000090a0
        a:000090b0
        a:000090b8
        a:000090c0
        a:000090d0
        0:00009000
1:VirtualAddress:a000 SizeOfBlock:50 Number:24
        a:0000a9a0
        a:0000a9a8
        a:0000a9b0
        a:0000a9b8
        a:0000a9c8
        a:0000ac80
        a:0000ac90
        a:0000aca0
        a:0000acb0
```


### 7.导出表

序号导出和名字导出都解析了
遍历的时候用了 unordered_map 库

```
IMAGE_EXPORT_DIRECTORY
        Name:GDI32.dll
        Base:1000
        NumberOfFunctions:1001
        NumberOfNames:973
3e8 00008000
3e9 00008020
3ea 00008040
3eb 00007f80
3ec 00004dd0
3ed 00008060
3ee 00007f60
3ef 00007fc0
3f0 0000d300
3f1 00007fe0
3f2 00007fa0
3f3 AbortDoc 0000cc40
3f4 AbortPath 00008340
3f5 00007ec0
3f6 DwmCreatedBitmapRemotingOutput 00009060
```
导出表中的中转函数
```
5f0 WaitForThreadpoolIoCallbacks 000aa90c => NTDLL.TpWaitForIoCompletion
5f1 WaitForThreadpoolTimerCallbacks 000aa948 => NTDLL.TpWaitForTimer
5f2 WaitForThreadpoolWaitCallbacks 000aa97c => NTDLL.TpWaitForWait
5f3 WaitForThreadpoolWorkCallbacks 000aa9af => NTDLL.TpWaitForWork
```

### 8.资源表

```
IMAGE_RESOURCE_DIRECTORY
1.资源类型字符串:AFX_DIALOG_LAYOUT
  1.自定义资源ID:66
     1.资源ID:804,代码页:804,文件偏移:2f860,长度（字节）:2
  2.自定义资源ID:105
     1.资源ID:1033,代码页:1033,文件偏移:2fb68,长度（字节）:2
     2.资源ID:2052,代码页:2052,文件偏移:2f858,长度（字节）:2
2.资源类型:3, Icon
  1.自定义资源ID:1
     1.资源ID:1033,代码页:1033,文件偏移:300a0,长度（字节）:7a8
  2.自定义资源ID:2
     1.资源ID:1033,代码页:1033,文件偏移:30848,长度（字节）:ff4
  3.自定义资源ID:3
     1.资源ID:1033,代码页:1033,文件偏移:31840,长度（字节）:1fc8
  4.自定义资源ID:4
     1.资源ID:1033,代码页:1033,文件偏移:33808,长度（字节）:468
  5.自定义资源ID:5
     1.资源ID:1033,代码页:1033,文件偏移:33c70,长度（字节）:10a8
  6.自定义资源ID:6
     1.资源ID:1033,代码页:1033,文件偏移:34d18,长度（字节）:25a8
3.资源类型:5, Dialog
  1.自定义资源ID:102
     1.资源ID:1033,代码页:1033,文件偏移:2f940,长度（字节）:228
     2.资源ID:2052,代码页:2052,文件偏移:2f610,长度（字节）:174
  2.自定义资源ID:105
     1.资源ID:1033,代码页:1033,文件偏移:2f868,长度（字节）:d2
     2.资源ID:2052,代码页:2052,文件偏移:2f788,长度（字节）:cc
4.资源类型:6, String
  1.自定义资源ID:7
     1.资源ID:1033,代码页:1033,文件偏移:2fd70,长度（字节）:72
     2.资源ID:2052,代码页:2052,文件偏移:2fb70,长度（字节）:42
  2.自定义资源ID:8
     1.资源ID:1033,代码页:1033,文件偏移:2fde8,长度（字节）:2b2
     2.资源ID:2052,代码页:2052,文件偏移:2fbb8,长度（字节）:1b8
5.资源类型:14, GroupIcon
  1.自定义资源ID:100
     1.资源ID:1033,代码页:1033,文件偏移:372c0,长度（字节）:5a
6.资源类型:16, Version
  1.自定义资源ID:1
     1.资源ID:0,代码页:0,文件偏移:2f428,长度（字节）:1e4
7.资源类型:24,
  1.自定义资源ID:1
     1.资源ID:0,代码页:0,文件偏移:2ee40,长度（字节）:5e1
     2.资源ID:1033,代码页:1033,文件偏移:37320,长度（字节）:17d
```