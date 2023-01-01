import std/[sets, tables, enumutils, times, segfaults, strutils, macros, options]

include pape/spec

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
  Dir* {.pure.} = enum
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
    Reserved # unused

  DataDirectory* = object
    virtualAddr*, virtualSize*: int

  ImportKind* {.pure.} = enum
    Ordinal
    Name

  Import* = object
    case kind*: ImportKind
    of ImportKind.Ordinal:
      ordinal*: int
    of Name:
      name*: string
    hint*: int
    address*: int         # address to which write the imported symbol

  ExportKind* {.pure.} = enum
    Real
    Forwarder

  Export* = object
    name*: Option[string]
    ordinal*: int
    case kind*: ExportKind
    of Real:
      address*: int
    of Forwarder:
      double*: string


  PEImage* = ref object
    magic*: PEMagic

    timestamp*: Time

    # sizes of
    size*: tuple[code, initializedData, uninitializedData, image, header: int]
    base*: tuple[image, code: int64, data: Option[int64]]
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
    coffCharacteristics*: set[COFFCharacteristics]

    entrypoint*: int
    subsystem*: WinSubsystem
    dllCharacteristics*: set[DLLCharacteristics]

    dirs*: Table[Dir, DataDirectory]
    sections*: seq[Section]

    # details
    imports*: Table[string, seq[Import]]
    exports*: tuple[
      timestamp: Time,
      ver: VerDouble,
      moduleName: string,
      ordinalBase: int,

      entries: seq[Export]
    ]


# exceptions
type
  PAPEDefect = object of Defect
  PAPEException = object of Exception

# helpers
proc isZeroMem[X](val: X): bool = 
  let sample = block:
    var r: X
    zeroMem(addr r, sizeof(X))
    r

  val == sample

proc resolve(p: PEImage, offset: int): ptr byte =
  result = nil 
  # resolve a virtual addr to file offset
  for s in p.sections:
    if offset >= s.virtualAddr and offset <= (s.virtualAddr + s.virtualSize):
      return cast[ptr byte](unsafeAddr(s.data[offset - s.virtualAddr]))

  raise PAPEException.newException("Can't resolve offset by virtual address: " & tohex(offset))


# parsing
type
  ParseInfo = ref object
    buffer: int

    dos: ptr DosHeaderRaw
    coff: ptr COFF
    pe: int

    optionalSize: int
    numberOfRvaAndSizes: int

converter toInt[T](x: ptr T): int = 
  cast[int](x)

proc toPtr[T](x: int): ptr T =
  cast[ptr T](x)

proc numToSet[T: enum, Y: SomeNumber](src: Y): set[T] = 
  assert sizeof(Y) == sizeof(T)

  for item in T:
    if (int64(ord(item)) and int64(src)) != 0:
      result.incl item  

macro enumRightRange(a: typed): untyped = 
  result = newNimNode(nnkBracket).add(a.getType[1][1..^1])

proc `$`(x: pointer): string = 
  var 
    arr = cast[ptr UncheckedArray[char]](x)
    index = 0

  while arr[index] != '\0':
    result.add arr[index]
    index.inc

using
  img: PEImage
  info: ParseInfo

proc parseExports(img, info) =
  if not img.dirs.contains Dir.Export: return
  let expDir = img.dirs[Dir.Export]
  if expDir.virtualAddr == 0 or expDir.virtualSize == 0: return

  let 
    exportDirTable = cast[ptr ExportDirectoryTableRaw](img.resolve(expDir.virtualAddr))
    exportAddrTable = cast[ptr UncheckedArray[int32]](img.resolve int exportDirTable.exportAddressRVA)
    exportNameTable = cast[ptr UncheckedArray[int32]](img.resolve int exportDirTable.namePointerRVA)
    exportOrdinalTable = cast[ptr UncheckedArray[uint16]](img.resolve int exportDirTable.ordinalTableRVA)

  var entries: Table[int, Export]

  for addrIndex in 0..<exportDirTable.adressTableEntries:
    let 
      ordinal = addrIndex.int + exportDirTable.ordinalBase.int
      posInMemory = exportAddrTable[addrIndex].int

    if (posInMemory >= expDir.virtualAddr) and posInMemory <= (expDir.virtualAddr + expDir.virtualSize):
      entries[ordinal] = Export(
        kind: ExportKind.Forwarder, ordinal: ordinal, double: $cast[pointer](img.resolve posInMemory)
      )
    else:
      entries[ordinal] = Export(
        kind: ExportKind.Real, ordinal: ordinal, address: exportAddrTable[addrIndex]
      )

  # index into ordinal table equals to index in name ptr table. So we will reverse this process to support
  # symbols without name
  for ordIndex in 0..<exportDirTable.numberOfNamePointer:
    let ordinalGot = exportOrdinalTable[ordIndex].int + exportDirTable.ordinalBase.int
    let namePtr = cast[pointer](img.resolve exportNameTable[ordIndex])

    var newName = $namePtr

    entries[ordinalGot.int].name = some(newName)

  for v in entries.mvalues:
    img.exports.entries.add move(v)


proc parseSections(img, info) = 
  let secRaw = cast[ptr UncheckedArray[PESectionRaw]](info.pe + info.optionalSize + sizeof(DataDirectoryRaw) * len(img.dirs))
  var currIndex = 0

  while (not isZeroMem secRaw[currIndex]) and (currIndex < info.coff.sectionsCount.int):
    let section = secRaw[currIndex]
    var result = Section(virtualSize: int section.virtualSize, virtualAddr: int section.virtualAddr)

    result.name = $cast[pointer](unsafeAddr(section.name))

    # characteristics
    for f in SectionFlags.enumRightRange:
      if (cast[uint32](ord(f)) and section.characteristics) != 0:
        result.characteristics.incl cast[SectionFlags](cast[uint32](ord(f)))

    
    # copy data
    if section.ptrToRaw != 0:
      result.data.setLen section.sizeOfRaw

      copyMem(
        addr result.data[0], 
        cast[pointer](info.buffer + section.ptrToRaw.int), 
        result.data.len
      )
      img.sections.add move(result)

    currIndex.inc

proc parseDataDirs(img, info) = 
  let dirsRaw = cast[ptr UncheckedArray[DataDirectoryRaw]](info.pe + info.optionalSize)

  for d in low(Dir)..Dir(info.numberOfRvaAndSizes-1):
    img.dirs[d] = DataDirectory(
      virtualAddr: int dirsRaw[d.ord].va, virtualSize: int dirsRaw[d.ord].size
    )

proc parseOptional[T: PE32Raw or PE64Raw](img, info) = 
  let pe = cast[ptr T](info.pe)

  info.optionalSize = sizeof(T)
  info.numberOfRvaAndSizes = int pe.numberOfRvaAndSizes

  img.size = (
    code: int pe.sizeOfCode, initializedData: int pe.sizeOfInitialized, 
    uninitializedData: int pe.sizeOfUnInitialized, image: int pe.sizeOfImage, 
    header: int pe.sizeOfHeaders
  )
  var bases = (image: int64 pe.imageBase, code: int64 pe.baseOfCode, data: none[int64]())
  when T is PE32Raw: bases.data = some(int64 pe.baseOfData)
  img.base = move(bases)

  img.alignment = (file: int pe.fileAlignment, section: int pe.sectionAlignment)

  img.ver = (
    image: (major: pe.majorImageVer.int, minor: pe.minorImageVer.int),
    os: (major: pe.majorOsVer.int, minor: pe.minorOsVer.int),
    subSystem: (major: pe.majorSubSystemVer.int, minor: pe.minorSubsytemVer.int),
    linker: (major: pe.majorLinker.int, minor: pe.minorLinker.int),
    win: int pe.win32VerValue
  )

  img.stack = (reserve: pe.sizeOfHeapReserve.int64, commit: pe.sizeOfStackCommit.int64)
  img.heap = (reserve: pe.sizeOfHeapReserve.int64, commit: pe.sizeOfHeapCommit.int64)

  img.entryPoint = int pe.entryPoint
  img.subsystem = pe.subSystem

  img.dllCharacteristics = numToSet[DLLCharacteristics, type(pe.dllCharacteristics)](pe.dllCharacteristics)

proc parse(img, info) = 
  info.dos = toPtr[DosHeaderRaw] info.buffer

  if info.dos.e_magic != ['M', 'Z']:
    raise PAPEDefect.newException("Invalid DOS magic signature")

  info.coff = toPtr[COFF] info.buffer + info.dos.e_lfanew.int

  if info.coff.magic != ['P', 'E', '\0', '\0']:
    raise PAPEDefect.newException("Invalid COFF magic signature")

  img.machine = info.coff.machine
  img.coffCharacteristics = numToSet[COFFCharacteristics, type(info.coff.characteristics)](info.coff.characteristics)
  img.timestamp = fromUnix((getTime().toUnix and (int64.high shl 32)) + info.coff.timestamp.int64)

  info.pe = info.coff + sizeof(COFF)
  img.magic = cast[ptr PEMagic](info.pe)[]

  if img.magic == PEMagic.PE32: parseOptional[PE32Raw](img, info)
  elif img.magic == PEMagic.PE64: parseOptional[PE64Raw](img, info)
  else:
    raise PAPEDefect.newException("Invalid Optional magic")

  img.parseDataDirs info
  img.parseSections info

  img.parseExports info

# ctor
proc newFromFile*(_: type PEImage, fileName: string): PEImage = 
  new result

  var 
    f = fileName.open
    buffer = alloc0(f.getFileSize)

  defer: buffer.dealloc

  discard f.readBuffer(buffer, f.getFileSize)
  var pi = ParseInfo(buffer: cast[int](buffer))
  
  result.parse pi
  
proc newFromPtr*(_: type PEImage, buffer: pointer): PEImage = 
  new result