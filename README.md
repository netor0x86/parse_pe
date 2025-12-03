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
这里需要处理 / 开头的节，暂时没有处理
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

### 4.导入表：
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
