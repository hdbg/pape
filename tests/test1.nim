# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import std/[unittest, os, options, tables, strutils, strformat, options]

import pape

let exePath = absolutePath("tests" / "Audacity.exe")

let d3d  = PEImage.newFromFile("tests" / "kernel32.dll") 

echo "#############"
for e in d3d.exports.entries:
  let n = if e.name.isSome(): e.name.get else: ""

  let addrS = if e.kind == ExportKind.Real: &"Addr: ({toHex(e.address)})" else: &"Forward: ({e.double})"

  echo &"Name: ({n}) Ord: ({e.ordinal.toHex}) {addrS}"

echo "#############"

# parsing
block:
  break

  suite "Loading":

    test "from file":
      var p = PEImage.newFromFile(exePath)
      # echo p.exports.entries

  var p = PEImage.newFromFile(exePath)
  suite "General info":
    test "coff":
      check: 
        p.machine == COFFMachine.AMD64
        p.coffCharacteristics == {
          COFFCharacteristics.ExecutableImage, CoffCharacteristics.LargeAddressAware
        }

    test "optional":
      check: 
        p.magic == PEMagic.PE64
        p.entryPoint == 0x14f79

        p.size == (
          code: 0xabb000, initializedData: 0x76a000, uninitializedData: 0,
          image: 0x122b000, header: 0x400
        )

        p.base == (
          image: 0x140000000'i64, code: 0x1000'i64, data: none[int64]()
        )

        p.alignment == (file: 0x200, section: 0x1000)
        p.subSystem == WinSubsystem.GUI

        p.stack == (reserve: 0x100000'i64, commit: 0x1000'i64)
        p.heap == (reserve: 0x100000'i64, commit: 0x1000'i64)

        p.dllCharacteristics == {DLLCharacteristics.DynamicBase, DLLCharacteristics.NxCompatible, DLLCharacteristics.TerminalServerAware, DLLCharacteristics.HighEntropyVA}

    test "data directories":
      check:
        p.dirs.len == 16

        p.dirs[Dir.Export] == DataDirectory(virtualAddr: 0xF1BB90, virtualSize: 0x61898)
        p.dirs[Dir.Import] == DataDirectory(virtualAddr: 0x1142E00, virtualSize: 0x58C)
        p.dirs[Dir.Resource] == DataDirectory(virtualAddr: 0x119A000, virtualSize: 0x3BD9C)
        p.dirs[Dir.Exception] == DataDirectory(virtualAddr: 0x10C8000, virtualSize: 0x623F4)
        p.dirs[Dir.Certificate] == DataDirectory(virtualAddr: 0x117B000, virtualSize: 0x2FE8)
        p.dirs[Dir.BaseRelocation] == DataDirectory(virtualAddr: 0x11D6000, virtualSize: 0x42A74)
        p.dirs[Dir.Debug] == DataDirectory(virtualAddr: 0xD68D70, virtualSize: 0x38)
        p.dirs[Dir.Architecture] == DataDirectory(virtualAddr: 0x0, virtualSize: 0x0)
        p.dirs[Dir.GlobalPtr] == DataDirectory(virtualAddr: 0x0, virtualSize: 0x0)
        p.dirs[Dir.TLS_Table] == DataDirectory(virtualAddr: 0xD73520, virtualSize: 0x28)
        p.dirs[Dir.LoadConfig] == DataDirectory(virtualAddr: 0xD68BF0, virtualSize: 0x140)
        p.dirs[Dir.BoundImport] == DataDirectory(virtualAddr: 0x0, virtualSize: 0x0)
        p.dirs[Dir.IAT_Table] == DataDirectory(virtualAddr: 0x1135000, virtualSize: 0xDE00)
        p.dirs[Dir.DelayImportDescriptor] == DataDirectory(virtualAddr: 0x0, virtualSize: 0x0)
        p.dirs[Dir.CLRRuntime] == DataDirectory(virtualAddr: 0x0, virtualSize: 0x0)
    
    test "sections":
      check:
        p.sections.len == 10

        p.sections[0].name == ".text"; p.sections[0].data.len == 0xABB000; p.sections[0].virtualAddr == 0x1000; p.sections[0].virtualSize == 0xABAE49
