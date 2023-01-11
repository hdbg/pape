import std/[times, segfaults]

import pape/[types, parse]

export pape.types

iterator iterRelocs*(img: PEImage): tuple[offset: int, kind: BaseRelocKind] = 
  for b in img.reloc:
    for r in b.relocs:
      yield (b.pageRVA + r.offset, r.kind)

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
  var pi = ParseInfo(buffer: cast[int](buffer))

  result.parse pi
  