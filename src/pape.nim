import std/[sets, tables, enumutils, times, segfaults, strutils, macros, options]

import pape/[types, parse]

export pape.types

# Front-end api


# helpers




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