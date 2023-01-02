import std/strutils
import types

proc isZeroMem*[X](val: X): bool = 
  let sample = block:
    var r: X
    zeroMem(addr r, sizeof(X))
    r

  val == sample

proc isNullMem*[X](val: ptr X): bool =
  result = true
  for a in cast[int](val)..(cast[int](val) + sizeof(X)):
    if cast[ptr uint8](a)[] != 0: return false

proc resolve*(p: PEImage, offset: int): ptr byte =
  result = nil 
  # resolve a virtual addr to file offset
  for s in p.sections:
    if offset >= s.virtualAddr and offset <= (s.virtualAddr + s.virtualSize):
      return cast[ptr byte](unsafeAddr(s.data[offset - s.virtualAddr]))

  raise PAPEException.newException("Can't resolve offset by virtual address: " & tohex(offset))