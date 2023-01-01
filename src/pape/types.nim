import std/[sets, tables, times, options]

import private/spec

export spec

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
  PAPEDefect* = object of Defect
  PAPEException* = object of Exception