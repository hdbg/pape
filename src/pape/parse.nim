import std/[sets, tables, enumutils, times, segfaults, macros, options, typetraits]

import types, helpers

# {.hint[HoleEnumConv]: off.}

type
  ParseOptions* {.pure.} = enum
    LoadSections
    LoadSectionsData

    LoadImports
    LoadExports
    LoadRelocs

  ParseInfo* = ref object
    buffer*: int

    dos: ptr DosHeaderRaw
    coff: ptr COFF
    pe: int

    optionalSize: int
    numberOfRvaAndSizes: int

    opts*: set[ParseOptions]

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

import strutils, strformat

proc parseReloc(img, info) = 
  if not img.dirs.contains Dir.BaseRelocation: return
  let relocDir = img.dirs[Dir.BaseRelocation]
  if relocDir.virtualAddr == 0 or relocDir.virtualSize == 0: return

  var
    currBlock = cast[ptr BaseRelocBlockRaw](img.resolve relocDir.virtualAddr) 
    totalParsedBytes = 0

  while totalParsedBytes < relocDir.virtualSize:
    var
      newBlock = BaseRelocBlock(pageRVA: currBlock.pageRVA.int)
      totalBlockBytes = 0
      currentReloc = cast[ptr uint16](cast[int](currBlock) + sizeof(BaseRelocBlockRaw))

    while totalBlockBytes < (currBlock.blockSize.int - sizeof(BaseRelocBlockRaw)):
      

      let 
        rawKind = (currentReloc[] and 0xf000) shr 12
        rawOffset = currentReloc[] and 0xfff

      # echo &"reloc: {tohex(currentReloc[])}, rawKind: {toHex(rawKind)}, rawOffset: {toHex(rawOffset)}"

      var relocKind: BaseRelocKind

      case rawKind
      of 0: relocKind = Absolute
      of 1: relocKind = High
      of 2: relocKind = Low
      of 3: relocKind = HighLow
      of 4: relocKind = HighAdj
      of 5:
        case img.machine
        of Mips16, MIPSFPU, MipsFpu16: relocKind = MipsJmpAddr
        of ARM, ARM64, Thumb: relocKind = ArmMov32
        of RISCV32, RISCV64, RISCV128: relocKind = RiscV_High20
        else: raise PAPEDefect.newException("Invalid platform for reloc type 5")
      of 7:
        case img.machine
        of Thumb: relocKind = Thumb_Mov32
        of RISCV32, RISCV64, RISCV128: relocKind = RiscV_Low12I
        else: raise PAPEDefect.newException("Invalid platform for reloc type 7")
      of 8:
        case img.machine
        of RISCV32, RISCV64, RISCV128: relocKind = RiscV_Low12S
        of LoongArch32: relocKind = LoongArch32_MarkLA
        of LoongArch64: relocKind = LoongArch64_MarkLa 
        else: raise PAPEDefect.newException("Invalid platform for reloc type 8")
      of 9:
        if img.machine notin [Mips16, MIPSFPU, MipsFpu16]:
          raise PAPEDefect.newException("Invalid platform for reloc type 9")
        relocKind = Mips_JmpAddr16
      of 10: relocKind = Dir64
      else:
        raise PAPEDefect.newException("Invalid reloc type: " & tohex(rawKind))

      newBlock.relocs.add BaseReloc(kind: relocKind, offset: int(rawOffset))
      # inc
      currentReloc = cast[type(currentReloc)](cast[int](currentReloc) + sizeof(uint16))
      totalBlockBytes.inc sizeof(uint16)

    # end raw block parsing
    img.reloc.add newBlock
    totalParsedBytes.inc currBlock.blockSize.int
    currBlock = cast[type(currBlock)](cast[int](currBlock) + int(currBlock.blockSize))


proc parseImports[T: PE32Raw or PE64Raw](img, info) = 
  if (not img.dirs.contains Dir.Import) or LoadImports notin info.opts: return
  let impDir = img.dirs[Dir.Import]
  if impDir.virtualAddr == 0 or impDir.virtualSize == 0: return

  let importDirTables = cast[ptr UncheckedArray[ImportDirectoryTableRaw]](img.resolve impDir.virtualAddr)
  var currDirIndex = 0

  while not helpers.isNullMem(unsafeAddr(importDirTables[currDirIndex])):
    var newModule = ModuleImport()

    newModule.name = $cast[pointer](img.resolve int importDirTables[currDirIndex].nameRVA)

    when T is PE32Raw:
      type BackEndNum =  uint32
    else:
      type BackEndNum =  uint64

    let 
      lookup = cast[ptr UncheckedArray[BackEndNum]](img.resolve int importDirTables[currDirIndex].importLookupTableRva)
      addrTable = cast[type(lookup)](img.resolve int importDirTables[currDirIndex].importAddressTableRVA)
    var currIndex = 0

    while lookup[currIndex] != 0:
      const 
        ordMask = when T is Pe32Raw: BackEndNum(0x80000000'u32) else: BackEndNum(0x8000000000000000'u64) 
        ordMaskNumber = BackEndNum(uint16.high) # 2 lower bytes
        hintNameTableRvaMask = BackEndNum(uint32.high and not(1'u32 shl 32))

      let 
        currLookup = lookUp[currIndex]
        origThunk = cast[int](addr(lookUp[currIndex]))
        thunk = cast[int](addr(addrTable[currIndex]))

      # echo &"OrdMask: {toHex(ordMask)}({ordMask}), ordMaskNumber: {toHex(ordMaskNumber)}, hintTable: {toHex(hintNameTableRvaMask)}"

      if (ordMask and currLookup) != 0:
        # import by ord
        let ordinal = int(currLookup and ordMaskNumber)
        newModule.entries.add Import(kind: ImportKind.Ordinal, ordinal: ordinal, thunk: thunk, originalThunk: origThunk)
      else:
        # import by name
        let 
          hintTable = img.resolve(int(hintNameTableRvaMask and currLookup))
          hint = int(cast[ptr uint16](hintTable)[])
          name = $cast[pointer](hintTable + sizeof(uint16))

        newModule.entries.add Import(kind: ImportKind.Name, name: name, hint: hint, thunk: thunk, originalThunk: origThunk)
      
      currIndex.inc

    img.imports.add newModule

    # inc dir
    currDirIndex.inc


proc parseExports(img, info) =
  if (not img.dirs.contains Dir.Export) or LoadExports notin info.opts: return
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
  if LoadSections notin info.opts: return

  let secRaw = cast[ptr UncheckedArray[PESectionRaw]](info.pe + info.optionalSize + sizeof(DataDirectoryRaw) * len(img.dirs))
  var currIndex = 0

  while (not isZeroMem secRaw[currIndex]) and (currIndex < info.coff.sectionsCount.int):
    let section = secRaw[currIndex]
    var result = Section(virtualSize: int section.virtualSize, virtualAddr: int section.virtualAddr, rawSize: int section.sizeOfRaw)

    result.name = $cast[pointer](unsafeAddr(section.name))

    # characteristics
    for f in SectionFlags.enumRightRange:
      if (cast[uint32](ord(f)) and section.characteristics) != 0:
        result.characteristics.incl cast[SectionFlags](cast[uint32](ord(f)))

    
    # copy data
    if (section.ptrToRaw != 0) and LoadSectionsData in info.opts:
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

proc parse*(img, info) = 
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

  if img.magic == PEMagic.PE32: parseImports[PE32Raw](img, info)
  elif img.magic == PEMagic.PE64: parseImports[PE64Raw](img, info)

  img.parseReloc info