# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import std/[unittest, os, options, tables]

import pape

let exePath = absolutePath("tests" / "subjects" / "Audacity.exe")


proc audacityVerify(p: PEImage) = 
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

        p.sections[0].name == ".text";  p.sections[0].data.len == 0xABB000; p.sections[0].virtualAddr == 0x1000; p.sections[0].virtualSize == 0xABAE49
        # p.sections[1].name == ".rdata"; p.sections[1].data.len == 0x34000; p.sections[1].virtualAddr == 0x7F000; p.sections[1].virtualSize == 0x337A4
        # p.sections[2].name == ".data";  p.sections[2].data.len == 0x1000; p.sections[2].virtualAddr == 0xB3000; p.sections[2].virtualSize == 0x12E4
        # p.sections[3].name == ".pdata"; p.sections[3].data.len == 0x6000; p.sections[3].virtualAddr == 0xB5000; p.sections[3].virtualSize == 0x5544
        # p.sections[4].name == ".didat"; p.sections[4].data.len == 0x1000; p.sections[4].virtualAddr == 0xBB000; p.sections[4].virtualSize == 0xA8
        # p.sections[5].name == ".rsrc";  p.sections[5].data.len == 0x1000; p.sections[5].virtualAddr == 0xBC000; p.sections[5].virtualSize == 0x520
        # p.sections[6].name == ".reloc"; p.sections[6].data.len == 0x1000; p.sections[6].virtualAddr == 0xBD000; p.sections[6].virtualSize == 0x348

    test "imports":
      var someImports = {"lib-transactions.dll": @[
        Import(kind: ImportKind.Name, name: "??1TransactionScopeImpl@@UEAA@XZ", thunk: 0x115e0a8, hint: 0x5),
        Import(kind: ImportKind.Name, name: "??0TransactionScope@@QEAA@AEAVAudacityProject@@PEBD@Z", thunk: 0x115dec2, hint: 0x1),
        Import(kind: ImportKind.Name, name: "??1TransactionScope@@QEAA@XZ", thunk: 0x115defa, hint: 0x4),
        Import(kind: ImportKind.Name, name: "?Commit@TransactionScope@@QEAA_NXZ", thunk: 0x115df1a, hint: 0xF),
        Import(kind: ImportKind.Name, name: "?Assign@?$GlobalVariable@UFactory@TransactionScope@@$$CBV?$function@$$A6A?AV?$unique_ptr@VTransactionScopeImpl@@U?$default_delete@VTransactionScopeImpl@@@std@@@std@@AEAVAudacityProject@@@Z@std@@$0A@$00@@CA?AV?$function@$$A6A?AV?$unique_ptr@VTransactionScopeImpl@@U?$default_delete@VTransactionScopeImpl@@@std@@@std@@AEAVAudacityProject@@@Z@std@@$$QEAV23@@Z", thunk: 0x115df40, hint: 0xE),
        Import(kind: ImportKind.Name, name: "??0TransactionScopeImpl@@QEAA@XZ", thunk: 0x115e0cc, hint: 0x3),
      ]}.toTable

      echo p.imports


block:
  suite "Loading":

    test "from file":
      var p = PEImage.newFromFile(exePath)
      # echo p.exports.entries
      p.audacityVerify

  var p = PEImage.newFromFile(exePath)
  
    
