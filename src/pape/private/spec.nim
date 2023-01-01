type
  COFFMachine* {.pure, size:2.} = enum
    Unk = 0
    i386 = 0x14c
    R4000 = 0x166
    WCEMIPSv2 = 0x169
    SH3 = 0x1a2
    SH3DSP = 0x1a3
    SH4 = 0x1a6
    SH5 = 0x1a8
    ARM = 0x1c0
    Thumb = 0x1c2
    
    ARMNT = 0x1c4
    AM33 = 0x1d3
    POWERPC = 0x1f0
    POWERPCFP = 0x1f1
    ia64 = 0x200
    MIPS16 = 0x266
    MIPSFPU = 0x366
    MIPSFPU16 = 0x466
    
    EBC = 0xebc
    RISCV32 = 0x5032
    RISCV64 = 0x5064
    RISV128 = 0x5128
    LoongArch32 = 0x6232
    LoongArch64 = 0x6264
    
    AMD64 = 0x8664
    M32R = 0x9041
    ARM64 = 0xaa64
    
  COFFCharacteristics* {.pure, size:2.} = enum
    RelocsStripped = 0x0001
    ExecutableImage = 0x0002
    FileLineNumsStripped = 0x0004
    LocalSymsStripped = 0x0008
    AgressiveWsTrim = 0x0010
    LargeAddressAware = 0x0020
    BytesReversedLo = 0x0080
    Bitness32Machine = 0x0100
    DebugStripped = 0x0200
    RemovableRunFromSwap = 0x0400
    NetRunFromSwap = 0x0800
    System = 0x1000
    Dll = 0x2000
    SystemOnly = 0x4000
    BytesReverseHi = 0x8000

  WinSubsystem* {.pure, size:2.} = enum
    Unk = 0, Native, GUI, CUI, OS2_CUI, 
    POSIX_CUI, EFIApp, EfiBootServiceDriver, EfiRuntimeDriver, EfiRom,
    XBox, WindowsBootApplication

  DLLCharacteristics* {.pure, size:2.} = enum
    HighEntropyVA = 0x0020
    DynamicBase = 0x0040
    ForceIntegrity = 0x0080
    NxCompatible = 0x0100
    NoIsolation = 0x0200
    NoSEH = 0x0400
    NoBind = 0x0800
    AppContainer = 0x1000
    WDMDriver = 0x2000
    GuardCF = 0x4000
    TerminalServerAware = 0x8000
  
  DosHeaderRaw* = object
    e_magic*: array[2, char]
    e_cblp, e_cp, e_crlc, e_cparhdr, e_min_alloc, e_maxalloc: uint16
    e_ss, e_esp, e_csym, e_ip, e_cs, e_lfarlc, e_ovno: uint16
    e_res1: array[8, char]
    e_oemid, e_oeminfo: uint16
    e_res2: array[0x14, char]
    e_lfanew*: uint32

  COFF* = object
    magic*: array[4, char]
    machine*: COFFMachine
    sectionsCount*: uint16
    timestamp*: uint32
    ptrSymbolTable: uint32
    numOfSymbols*: uint32
    sizeOfOptional*: uint16
    characteristics*: uint16

  PEMagic* {.pure, size:2.} = enum
    PE32 = 0x10b
    PE64 = 0x20b

  DataDirectoryRaw* = object
    va*, size*: uint32

  PE32Raw* {.packed.} = object
    magic*: PEMagic
    majorLinker*, minorLinker*: uint8
    sizeOfCode*: uint32
    sizeOfInitialized*, sizeOfUnInitialized*: uint32
    entryPoint*, baseOfCode*, baseOfData*: uint32

    # common
    imageBase*: uint32
    sectionAlignment*, fileAlignment*: uint32

    majorOSVer*, minorOsVer*: uint16
    majorImageVer*, minorImageVer*: uint16
    majorSubSystemVer*, minorSubsytemVer*: uint16
    win32VerValue*: uint32

    sizeOfImage*, sizeOfHeaders*, checkSum*: uint32
    subSystem*: WinSubsystem
    dllCharacteristics*: uint16

    sizeOfStackReserve*, sizeOfStackCommit*, sizeOfHeapReserve*, sizeOfHeapCommit*: uint32
    ldrFlags: uint32

    numberOfRvaAndSizes*: uint32

  PE64Raw* {.packed.} = object
    magic*: PEMagic
    majorLinker*, minorLinker*: uint8
    sizeOfCode*: uint32
    sizeOfInitialized*, sizeOfUnInitialized*: uint32
    entryPoint*, baseOfCode*: uint32

    # common
    imageBase*: uint64
    sectionAlignment*, fileAlignment*: uint32

    majorOSVer*, minorOsVer*: uint16
    majorImageVer*, minorImageVer*: uint16
    majorSubSystemVer*, minorSubsytemVer*: uint16
    win32VerValue*: uint32

    sizeOfImage*, sizeOfHeaders*, checkSum*: uint32
    subSystem*: WinSubsystem
    dllCharacteristics*: uint16

    sizeOfStackReserve*, sizeOfStackCommit*, sizeOfHeapReserve*, sizeOfHeapCommit*: uint64
    ldrFlags: uint32

    numberOfRvaAndSizes*: uint32

  #[
    - DOS
    - COFF
    - PE32/PE64
    - DataDirs
    - Sections
  ]#

  SectionFlags* {.pure, size:8.} = enum

    NoPad =                     0x00000008
    ContainsCode =              0x00000020
    ContainsInitializedData =   0x00000040
    ContainsUnInitializedData = 0x00000080
    LinkInfo =                  0x00000200
    LinkRemove =                0x00000800
    ComDat =                    0x00001000
    GPRelative =                0x00008000

    AlignOnByte =               0x00100000
    AlignOn2Bytes =             0x00200000
    AlignOn4Bytes =             0x00300000
    AlignOn8Bytes =             0x00400000
    AlignOn16Bytes =            0x00500000
    AlignOn32Bytes =            0x00600000
    AlignOn64Bytes =            0x00700000
    AlignOn128Bytes =           0x00800000
    AlignOn256Bytes =           0x00900000
    AlignOn512Bytes =           0x00A00000
    AlignOn1024Bytes =          0x00B00000
    AlignOn2048Bytes =          0x00C00000
    AlignOn4096Bytes =          0x00D00000
    AlignOn8192Bytes =          0x00E00000

    ExtendedRelocations =       0x01000000
    Discardable =               0x02000000
    MemNotCached =              0x04000000
    MemNotPaged =               0x08000000
    MemShared =                 0x10000000
    MemExecute =                0x20000000
    MemRead =                   0x40000000
    MemWrite =                  0x80000000

  PESectionRaw* {.packed.} = object
    name*: array[8, char]
    virtualSize*, virtualAddr*: uint32

    sizeOfRaw*, ptrToRaw*: uint32
    ptrToRelocs*, ptrToLines*: uint32
    numberOfRelocs*, numberOfLineNumbers*: uint16

    characteristics*: uint32 #   implement via hash set

  ImportDirectoryTableRaw* {.packed.} = object
    importLookupTableRva*, timeDataStamp*, forwaderChain*, nameRVA*, importAddressTableRVA*: uint32

  ExportDirectoryTableRaw* {.packed.} = object
    exportFlags: uint32
    timeDateStamp*: uint32
    majorVer*, minorVer*: uint16

    nameRVA*, ordinalBase*: uint32
    adressTableEntries*: uint32

    numberOfNamePointer*: uint32
    exportAddressRVA*: uint32
    namePointerRVA*: uint32
    ordinalTableRVA*: uint32