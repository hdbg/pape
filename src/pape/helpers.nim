import std/strutils
import types

proc isZeroMem*[X](val: X): bool = 
  let sample = block:
    var r: X
    zeroMem(addr r, sizeof(X))
    r

  val == sample

proc resolve*(p: PEImage, offset: int): ptr byte =
  result = nil 
  # resolve a virtual addr to file offset
  for s in p.sections:
    if offset >= s.virtualAddr and offset <= (s.virtualAddr + s.virtualSize):
      return cast[ptr byte](unsafeAddr(s.data[offset - s.virtualAddr]))

  raise PAPEException.newException("Can't resolve offset by virtual address: " & tohex(offset))