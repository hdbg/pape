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

  DataDirectory* = object
    virtualAddr*, virtualSize*: int

  ImportKind* {.pure.} = enum
    Ordinal
    Name

  Import* = object
    module*: string
    case kind*: ImportKind
    of ImportKind.Ordinal:
      ordinal*: int
    of Name:
      name*: string
    hint*: int
    address*: int         # address to which write the imported symbol

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
    imports*: seq[Import]


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

proc seek[T](p: PEImage, offset: int): T = 
  cast[T](cast[int](p.buffer) + offset)

# parsing
type
  ParseInfo = ref object
    buffer: int

    dos: ptr DosHeaderRaw
    coff: ptr COFF
    pe: int

converter toInt[T](x: ptr T): int = 
  cast[int](x)

proc toPtr[T](x: int): ptr T =
  cast[ptr T](x)

proc numToSet[T: enum, Y: SomeNumber](src: Y): set[T] = 
  assert sizeof(Y) == sizeof(T)

  for item in T:
    if (int64(ord(item)) and int64(src)) != 0:
      result.incl item  

proc parseOptional[T: PE32Raw or PE64Raw](img: PEImage, info: ParseInfo) = 
  let pe = cast[ptr T](info.pe)

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

proc parse(img: PEImage, info: ParseInfo) = 
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