import std/[sets, tables, enumutils, times, segfaults, macros, options, typetraits]

import types, helpers

# {.hint[HoleEnumConv]: off.}

type
  ParseInfo* = ref object
    buffer*: int

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

proc parseImports[T: PE32Raw or PE64Raw](img, info) = 
  if not img.dirs.contains Dir.Import: return
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