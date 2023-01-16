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

