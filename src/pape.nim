import std/[times, segfaults]

import pape/[types, parse]

export pape.types
export parse.ParseOptions

const
  defParseOptions = {
    ParseOptions.LoadSections, ParseOptions.LoadSectionsData,
    ParseOptions.LoadImports, ParseOptions.LoadExports, ParseOptions.LoadRelocs
  }
iterator iterRelocs*(img: PEImage): tuple[offset: int, kind: BaseRelocKind] = 
  for b in img.reloc:
    for r in b.relocs:
      yield (b.pageRVA + r.offset, r.kind)

# ctor
proc newFromFile*(_: type PEImage, fileName: string, opts: set[ParseOptions] = defParseOptions): PEImage = 
  new result

  var 
    f = fileName.open
    buffer = alloc0(f.getFileSize)

  defer: buffer.dealloc

  discard f.readBuffer(buffer, f.getFileSize)
  var pi = ParseInfo(buffer: cast[int](buffer), opts: opts)
  
  result.parse pi
  
proc newFromPtr*(_: type PEImage, buffer: pointer, opts: set[ParseOptions] = defParseOptions): PEImage = 
  new result
  var pi = ParseInfo(buffer: cast[int](buffer), opts: opts)

  result.parse pi
  