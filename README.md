# BattlEye kick crash fix for Conan Exiles dedicated servers

A single drop-in file, `winmm.dll`, that stops BattlEye kicks from crashing your server. It needs no installer,
service, website or config. Self-hosted Windows servers only (you need access to the server's files).

**Supported game build:** Steam build **26552396** (the Akhamet update, 13 November 2026). On any other build
the file does nothing and the server runs as normal.

## What's going on

Since the Akhamet update, **every time BattlEye kicks a player, the whole server crashes** instead of just
disconnecting that player. You'll see crash loops every few minutes when a player's BattlEye keeps failing,
most often with the reason **"Query Timeout"** (BattlEye on the player's PC stopped answering the server). Many
official servers went down this way on 13 November too.

The cause is a bug in the game's server code. When BattlEye asks the server to kick a player, the game looks up
the world through a cached pointer that a dedicated server never sets. It reads through a null pointer and
crashes (an access violation in `UGameInstance::GetWorld`). In `ConanSandbox.log` the last lines before each crash
look like this:

```
BattlEyeLogging: Warning: BattlEyeServer: BattlEye kicked the player 4 because: Query Timeout
LogWindows: Error: Unhandled Exception: EXCEPTION_ACCESS_VIOLATION reading address 0x0000000000000030
```

## What this fix does

1. **Stops the crash.** When BattlEye kicks a player, the fix points the game at the server's own live game
   instance just for that moment. The game then kicks the player the way it was designed to, and the pointer is
   set back afterwards. If anything can't be checked, the kick is skipped and the player stays connected, so a
   kick never crashes the server.
2. **Tells the player why.** Normally a kicked player only sees "Connection lost". With the fix, they get a
   message box titled **"Disconnected by BattlEye"** with the reason and how to fix it (restart the game,
   reinstall BattlEye, verify game files, check their firewall or antivirus). The kick follows 3 seconds later.

Nothing else in the game is changed: no gameplay, no saves, no database. BattlEye itself keeps working as normal.
It's only the crash that's removed.

### Is it safe?

- Every game address the fix uses is found at startup from the game's own code and checked byte for byte.
  The fix also checks that the server executable is exactly build 26552396. If anything doesn't match, for example
  after Funcom patches the game, the fix writes why to its log and does nothing.
- `winmm.dll` is a standard Windows library that the server loads from its own folder first. This file passes
  every call through to the real Windows `winmm.dll` in `System32` unchanged, and adds the fix on top.

## Install

1. **Stop the server.**
2. Copy `winmm.dll` into the server's `ConanSandbox\Binaries\Win64\` folder, the one that contains
   `ConanSandboxServer-Win64-Shipping.exe`.
   - If a `winmm.dll` is already there, another tool is using the same method. Don't overwrite it without
     checking what it is.
3. **Start the server.**

## Check it's working

About 30 seconds after the server starts, `BattlEyeFix.log` appears next to `winmm.dll`. Look for:

```
Guard armed: a BattlEye kick can no longer crash the server
Guard ready: game instance > world > ConanGameMode > GameSession validated
Kick message armed: players see why, then are kicked 3 s later
```

"Guard ready" appears once the map has loaded. Each kick is logged as well:

```
BattlEye kick of player 0 (Query Timeout): kicked safely
Kick message shown, kick follows in 3 s
Held kick done (Query Timeout)
```

If you see `Patch off, server runs unchanged: ...` instead, the fix found something it didn't expect and isn't
active. The most common cause is a different game build.

## Options

Create an empty file next to `winmm.dll` with one of these names:

| File | Effect |
|---|---|
| `BattlEyeFix.notice-off` | No message box: kicks happen immediately. The crash fix stays on. Takes effect within a second. |
| `BattlEyeFix.disabled` | Turns the fix off completely at the next server start. |

## Uninstall

Stop the server, delete `winmm.dll` (and `BattlEyeFix.log` if you like), then start the server.

## When Funcom fixes it

Once Funcom ships a game update, this file switches itself off because the build no longer matches. Remove it
when convenient.

## For players who get kicked

A "Query Timeout" kick means BattlEye on the player's own PC stopped responding. It's usually fixed by:

1. Restarting the game.
2. Reinstalling BattlEye: close the game, open the Conan Exiles install folder, go to
   `ConanSandbox\Binaries\Win64\BattlEye`, run `Uninstall_BattlEye.bat`, then `Install_BattlEye.bat`.
3. Verifying the game files in Steam.
4. Making sure a firewall or antivirus isn't blocking BattlEye.

## Building from source

| Path | What it is |
|---|---|
| `src/BattlEyeFix.cpp` | The whole fix and the `winmm.dll` pass-through |
| `src/BattlEyeFix.def` | The `winmm.dll` exports the server uses |
| `src/Engine.h`, `src/Common.h` | Memory-read and logging helpers |
| `third_party/minhook/` | [MinHook](https://github.com/TsudaKageyu/minhook) 1.3.4, BSD 2-clause (see its `LICENSE.txt`) |

Build with [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) (the `ucrt-x86_64` release):

```powershell
.\build.ps1 -Toolchain C:\path\to\llvm-mingw-<version>-ucrt-x86_64
```

The DLL is written to `out\winmm.dll`, and the script prints its SHA-256.
