# pape
> Pure Nim PE parsing library

## How-to use
```nim
import pape
import std/[times, strutils, options]

var img = PEImage.newFromFile(r"C:\Windows\System32\kernel32.dll")

echo img.magic == PEMagic.PE64 # true
echo $img.timestamp            # 2038-08-04T14:50:58+03:00

echo img.ver.image             # (major: 10, minor: 0)
echo toHex img.entryPoint      # 0x0000000000015640

for importMod in img.imports:
  echo importMod.name          # api-ms-win-core-rtlsupport-l1-1-0.dll, etc...

# GetThreadId, LocalFree, LocalHandle etc...
for exportEntry in img.exports.entries: 
  if exportEntry.name.isSome:
    echo get(exportEntry.name)
```