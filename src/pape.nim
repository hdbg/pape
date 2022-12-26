import std/[sets, tables, enumutils, typetraits, segfaults, strutils]

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
  
  DosHeaderRaw = object
    e_magic: array[2, char]
    e_cblp, e_cp, e_crlc, e_cparhdr, e_min_alloc, e_maxalloc: uint16
    e_ss, e_esp, e_csym, e_ip, e_cs, e_lfarlc, e_ovno: uint16
    e_res1: array[8, char]
    e_oemid, e_oeminfo: uint16
    e_res2: array[0x14, char]
    e_lfanew: uint32

  COFF* = object
    magic: array[4, char]
    machine*: COFFMachine
    sectionsCount*: uint16
    timestamp*: uint32
    ptrSymbolTable: uint32
    numOfSymbols*: uint32
    sizeOfOptional: uint16
    characteristics*: uint16

  PEMagic* {.pure, size:2.} = enum
    PE32 = 0x10b
    PE64 = 0x20b

  DataDirectoryRaw = object
    va, size: uint32

  PE32Raw {.packed.} = object
    magic: PEMagic
    majorLinker, minorLinker: uint8
    sizeOfCode: uint32
    sizeOfInitialized, sizeOfUnInitialized: uint32
    entryPoint, baseOfCode, baseOfData: uint32

    # common
    imageBase: uint32
    sectionAlignment, fileAlignment: uint32

    majorOSVer, minorOsVer: uint16
    majorImageVer, minorImageVer: uint16
    majorSubSystemVer, minorSubsytemVer: uint16
    win32VerValue: uint32

    sizeOfImage, sizeOfHeaders, checkSum: uint32
    subSystem: WinSubsystem
    dllCharacteristics: uint16

    sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve, sizeOfHeapCommit: uint32
    ldrFlags: uint32

    numberOfRvaAndSizes: uint32

  PE64Raw {.packed.} = object
    magic: PEMagic
    majorLinker, minorLinker: uint8
    sizeOfCode: uint32
    sizeOfInitialized, sizeOfUnInitialized: uint32
    entryPoint, baseOfCode: uint32

    # common
    imageBase: uint64
    sectionAlignment, fileAlignment: uint32

    majorOSVer, minorOsVer: uint16
    majorImageVer, minorImageVer: uint16
    majorSubSystemVer, minorSubsytemVer: uint16
    win32VerValue: uint32

    sizeOfImage, sizeOfHeaders, checkSum: uint32
    subSystem: WinSubsystem
    dllCharacteristics: uint16

    sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve, sizeOfHeapCommit: uint64
    ldrFlags: uint32

    numberOfRvaAndSizes: uint32

  #[
    - DOS
    - COFF
    - PE32/PE64
    - DataDirs
    - Sections
  ]#

  SectionFlags* {.pure, size:4.} = enum
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

  PESectionRaw {.packed.} = object
    name: array[8, char]
    virtualSize, virtualAddr: uint32

    sizeOfRaw, ptrToRaw: uint32
    ptrToRelocs, ptrToLines: uint32
    numberOfRelocs, numberOfLineNumbers: uint16

    characteristics: uint32 #   implement via hash set


# Front-end api
type
  VerDouble* = tuple[major, minor: int]

  Section* = object
    name*: string
    virtualSize*, virtualAddr*: int

    data*: seq[byte] # get raw data size by section.data.len
    characteristics*: HashSet[SectionFlags]

  #[
    Because data dirs order always preserved, but theirs count varies, we should indicate which are available
  ]#
  DataDirs* {.pure.} = enum
    Export
    Import
    Resource
    Exception
    Certificate
    BaseRelocation
    Debug
    Architecture
    GlobalPtr
    TLS_Table
    LoadConfig
    BoundImport
    IAT_Table
    DelayImportDescriptor
    CLRRuntime
    End # Reserved

  DataDirectory* = object
    virtualAddr, virtualSize: int

  MemInfo = object
    wasAlloc: bool
    count: int

  PE* = object
    buffer: ptr UncheckedArray[byte]
    mem: MemInfo  # indicator for destructor if buffer was allocated

    magic*: PEMagic

    # sizes of
    size*: tuple[code, initializedData, uninitializedData, image, header: int]
    base*: tuple[image, data, code: int]
    alignment*: tuple[file, section: int]

    # versions
    ver*: tuple[
      image: VerDouble,
      os: VerDouble,
      subSystem: VerDouble,
      linker: VerDouble,
      win: int
    ]

    # memory
    stack*: tuple[reserve, commit: int64]
    heap*: tuple[reserve, commit: int64]

    # coff related
    machine*: COFFMachine
    coffCharacteristics: set[COFFCharacteristics]

    entrypoint*: int
    subsystem*: WinSubsystem
    dllCharacteristics*: set[DLLCharacteristics]

    dataDirs*: Table[DataDirs, DataDirectory]
    sections*: seq[Section]

proc `=destroy`(x: var PE) = 
  if x.mem.wasAlloc and cast[pointer](x.buffer) != nil:
    dealloc cast[pointer](x.buffer)

proc `=copy`(dest: var PE, source: PE) = 
  copyMem(addr dest, unsafeAddr source, sizeof PE)

  # copy buffer
  if source.mem.wasAlloc:
    dest.buffer = cast[ptr UncheckedArray[byte]](alloc(source.mem.count))
    copyMem(dest.buffer, source.buffer, source.mem.count)

# helpers
proc seek[T](p: PE, offset: int): T = 
  cast[T](cast[int](p.buffer) + offset)

proc numToSet[T: enum, Y: SomeNumber](src: Y): set[T] = 
  assert sizeof(Y) == sizeof(T)

  for item in T:
    if (int64(ord(item)) and int64(src)) != 0:
      result.incl item  

proc parse(p: var PE) = 
  let asDos = cast[ptr DosHeaderRaw](p.buffer)
  doAssert asDos.e_magic == ['M', 'Z']

  let asCoff = seek[ptr COFF](p, asDos.e_lfanew.int)
  doAssert asCoff.magic == ['P', 'E', '\x00', '\0']

  p.machine = asCoff.machine
  p.coffCharacteristics =  numToSet[COFFCharacteristics, uint16](asCoff.characteristics)

  p.magic = cast[ptr PEMagic](cast[int](p.buffer) + sizeof(COFF) + asDos.e_lfanew.int)[]

  template common = 
    mixin rawPe
    p.ver.linker = (major: rawPe.majorLinker.int, minor: rawPe.minorLinker.int)
    p.size = (
      code: rawPe.sizeOfCode.int, initializedData: rawPe.sizeOfInitialized.int,
      uninitializedData: rawPe.sizeOfUnInitialized.int,
      image: rawPe.sizeOfImage.int, header: rawPe.sizeOfHeaders.int 
    )
    p.base = (
      image: rawPe.imageBase.int, data: -1, code: rawPe.baseOfCode.int
    )
    p.alignment = (
      file: rawPe.fileAlignment.int, section: rawPe.sectionAlignment.int
    )

    p.ver.os = (major: rawPe.majorOsVer.int, minor: rawPe.minorOsVer.int)

    p.ver.image = (major: rawPe.majorImageVer.int, minor: rawPe.minorImageVer.int)
    p.ver.subSystem = (major: rawPe.majorSubSystemVer.int, minor: rawPe.minorSubsytemVer.int)
    
    p.subSystem = rawPe.subSystem
    p.dllCharacteristics = numToSet[DLLCharacteristics, uint16](rawPe.dllCharacteristics)

    # debugEcho "Stack: ", rawPe.sizeOfHeapReserve

    p.stack = (reserve: rawPe.sizeOfHeapReserve.int64, commit: rawPe.sizeOfStackCommit.int64)
    p.heap = (reserve: rawPe.sizeOfHeapReserve.int64, commit: rawPe.sizeOfHeapCommit.int64)

    # parse data dirs
    let dataDirs = cast[ptr UncheckedArray[DataDirectoryRaw]](cast[int](rawPe) + sizeof(pointerBase(type rawPe)))
    for name in low(DataDirs)..DataDirs(rawPe.numberOfRvaAndSizes.int-1):
      if name == DataDirs.End: break
      let d = dataDirs[ord(name)]
      p.dataDirs[name] = DataDirectory(
        virtualAddr: int d.va, virtualSize: int d.size
      )

    # parse sections
    let 
      sections = cast[ptr UncheckedArray[PESectionRaw]](
        cast[int](rawPe) + sizeof(pointerBase(type rawPe)) + (sizeof(DataDirectoryRaw) * rawPe.numberOfRvaAndSizes.int)
      )
      emptySection = block:
        var res: PESectionRaw
        zeroMem unsafeAddr res, sizeof res
        res
    var currentSection = 0

    while sections[currentSection] != emptySection and currentSection < asCoff.sectionsCount.int:
      let curr = sections[currentSection]
      var newSection = Section(name: $curr.name, virtualSize: curr.virtualSize.int, virtualAddr: curr.virtualAddr.int)

      # var currFlag = low(SectionFlags)

      # while currFlag != high(SectionFlags):
      #   if (ord(currFlag) and curr.characteristics.int) != 0:
      #     newSection.characteristics.incl currFlag

      #   currFlag.succ

      newSection.data.setLen curr.sizeOfRaw

      copyMem(unsafeAddr(newSection.data[0]), cast[pointer](cast[int](p.buffer) + curr.ptrToRaw.int), curr.sizeOfRaw)
      p.sections.add move(newSection)

      currentSection.inc

  if p.magic == PEMagic.PE32:
    let rawPe = cast[ptr PE32Raw](cast[int](asCoff) + sizeof(COFF))
    common()

    p.base.data = rawPe.baseOfData.int
  else:
    let rawPe = cast[ptr PE64Raw](cast[int](asCoff) + sizeof(COFF))
    common()

# constructors

proc newFromFile*(_: type PE, name: string): PE = 
  var f = name.open
  # result.buffer.reserve f.getFileSize

  result.mem.wasAlloc = true
  result.mem.count = f.getFileSize.int

  result.buffer = cast[ptr UncheckedArray[byte]](alloc(f.getFileSize))

  discard f.readBuffer(cast[pointer](result.buffer), f.getFileSize)

  result.parse

proc newFromPtr*(_: type PE, address: pointer): PE = 
  result.mem.wasAlloc = false
  result.buffer = cast[ptr UncheckedArray[byte]](address)

