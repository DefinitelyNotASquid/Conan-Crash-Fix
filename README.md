# BattlEye fixes for Conan Exiles dedicated servers

A single drop-in file, `winmm.dll`, for self-hosted Windows servers. It needs no installer, service, website or
config:

1. **Crash guard.** Stops BattlEye kicks from crashing your whole server.
2. **Kick message.** Tells kicked players why, instead of just "Connection lost".
3. **BattlEye monitor.** Spots when BattlEye's own servers start kicking innocent players, and shows you in
   a status file and an event log.
4. **BattlEye re-check (optional, off by default).** Instead of kicking a player BattlEye wrongly rejected, the
   server asks BattlEye to check them again until it gets it right.

**Supported game build:** Steam build **26552396** (the Akhamet update, 13 November 2026). On any other build the
file does nothing and the server runs as normal.

Free community tool (MIT). Not affiliated with Funcom or BattlEye.

## What's going on

### 1. BattlEye kicks crash the server

Since the Akhamet update, **every time BattlEye kicks a player, the whole server crashes** instead of just
disconnecting that player. You'll see crash loops every few minutes when a player's BattlEye keeps failing. Many
official servers went down this way on 13 November too.

The cause is a bug in the game's server code. When BattlEye asks the server to kick a player, the game looks up
the world through a cached pointer that a dedicated server never sets. It reads through a null pointer and
crashes (an access violation in `UGameInstance::GetWorld`). In `ConanSandbox.log` the last lines before each crash
look like this:

```
BattlEyeLogging: Warning: BattlEyeServer: BattlEye kicked the player 4 because: Query Timeout
LogWindows: Error: Unhandled Exception: EXCEPTION_ACCESS_VIOLATION reading address 0x0000000000000030
```

### 2. BattlEye's servers kick players who did nothing wrong

On 14 November, from about 06:30 to past 19:00 (UTC+11), BattlEye kept kicking players with
**"Client not responding"** 10 to 60 seconds after they joined, on every server we looked at:

- One production server logged 178 of these kicks in one day, and a freshly started test server got the same.
- It came and went in windows, about 13 bad ones in a day and up to 90 minutes long, **switching for every
  server at the same moment**.
- Players who were already in the game were never affected. Only new joins were.
- Reinstalling BattlEye, verifying game files, new characters and firewall changes made no difference.

We captured exactly what happens, from the game's BattlEye log and the server's network traffic:

| Time | BattlEye's servers ↔ game server | Game server ↔ player |
|---|---|---|
| +0.0 s | BattlEye's servers send a check | the check is passed on to the player |
| +0.4 s | | **the player's BattlEye answers** (926 bytes) |
| +0.4 s | the answer is passed on to BattlEye's servers within 1 ms | |
| +0.9 s | **BattlEye's servers reply: kick, "Client not responding"** | the player is kicked |

So the player's PC did respond. The game server passed everything on correctly. The decision to kick came from
**BattlEye's central servers**, which rejected valid answers. The kick reason is misleading, so players spend
hours reinstalling and firewalling for nothing.

## Why depending on this is a problem

This is worth thinking about as a server owner, whether or not you use this tool.

- **Your anti-cheat only works while BattlEye's infrastructure works.** The server's BattlEye file doesn't
  decide anything: it relays checks to and from BattlEye's servers, and the verdict comes back from them. When
  their side misbehaves, your server can't protect players and can't stop the false kicks either.
- **When it fails, it fails everywhere at once.** One problem on BattlEye's side becomes a fault on every Conan
  server at the same moment: a single point of failure for the whole community.
- **You get no warning and no explanation.** There's nothing in the server log, no reconnect, no error and no
  version change: only a stream of "Client not responding" kicks that look like your players' problem. We only
  found the cause by capturing packets.
- **The choices are bad.** Leave BattlEye on, and new players can't get in for hours. Turn it off, and your
  server has no anti-cheat. Neither should be your problem to solve.
- **Players blame you, or themselves.** They see a kick that says their PC isn't responding. They reinstall,
  change firewall settings, verify files and remake characters, then give up on your server.
- **It's out of your hands.** BattlEye's checks change live and aren't tied to game updates, so nothing you
  install or configure decides which version runs. It also happened on a weekend.

An anti-cheat that kicks innocent players whenever its own servers have a bad hour is a real cost to every
community that depends on it. Server owners should be able to see when it's failing and choose what happens
next. This tool gives you both.

## What this tool does

1. **Crash guard.** When BattlEye kicks a player, the fix points the game at the server's own live game instance
   just for that moment. The game then kicks the player the way it was designed to, and the pointer is set back
   afterwards. If anything can't be checked, the kick is skipped and the player stays connected, so a kick never
   crashes the server.
2. **Kick message.** A kicked player gets a message box titled **"Disconnected by BattlEye"** with the reason
   and what to try. The kick follows 3 seconds later.
3. **BattlEye monitor (always on).** Every BattlEye kick is checked against the player's own BattlEye traffic. A
   **"Client not responding"** kick that arrives right after the player's BattlEye *did* respond, during the join
   check, is flagged as a **suspected false kick**. Several of those in a short time means BattlEye is
   **degraded**. The next player who passes the join check means it has **recovered**. All of it goes to the
   log, `BattlEyeFix.status.json` and `BattlEyeFix.events.jsonl` (see [Monitoring](#monitoring)).
   On its own, the monitor never changes what happens to players.
4. **BattlEye re-check (off unless you turn it on).** A suspected false kick is **not carried out**. Instead the
   player stays in game, is told what's going on, is taken off BattlEye, and is registered again a little later,
   the same way the game does when a player joins. BattlEye then runs a fresh check. If BattlEye has recovered,
   the player passes and is protected again without ever reconnecting. If it's still broken, this repeats until
   your time limit, and then the player is kicked as normal.

Nothing else in the game is changed: no gameplay, no saves, no database.

### Is it safe?

- Every game address the fix uses is found at startup from the game's own code and checked byte for byte.
  The fix also checks that the server executable is exactly build 26552396. If anything doesn't match, for example
  after Funcom patches the game, the fix writes why to its log and does nothing.
- `winmm.dll` is a standard Windows library that the server loads from its own folder first. This file passes
  every call through to the real Windows `winmm.dll` in `System32` unchanged, and adds the fix on top.
- The re-check uses the game's own functions to remove and add players, the ones it calls when players join and
  leave. It doesn't fake, replay or change any BattlEye data.
- Each re-check step takes about 0.3-0.5 ms on the game thread. In testing, no frame took longer because of it.

## Install

1. **Stop the server.**
2. Download `winmm.dll` from [Releases](../../releases) and copy it into the server's
   `ConanSandbox\Binaries\Win64\` folder, the one that contains `ConanSandboxServer-Win64-Shipping.exe`.
   - If a `winmm.dll` is already there, another tool is using the same method. Don't overwrite it without
     checking what it is.
3. **Start the server.**

This gives you the crash guard, the kick message and the monitor. The re-check stays off until you turn it on.

## Check it's working

About 30 seconds after the server starts, `BattlEyeFix.log` appears next to `winmm.dll`. Look for:

```
Guard armed: a BattlEye kick can no longer crash the server
BattlEye interface found: received slot 0xaba1708, register 0x4d18a20, unregister 0x4d22890, login step 0x4d1a8f0
BattlEye monitor armed; re-check off (create BattlEyeFix.recheck to turn it on)
Guard ready: game instance > world > ConanGameMode > GameSession validated
Kick message armed: players see why, then are kicked 3 s later
```

BattlEye only loads when the first player joins. After that you'll also see `BattlEye monitor: packet tracking on`.

If you see `Patch off, server runs unchanged: ...` instead, the fix found something it didn't expect and isn't
active. The most common cause is a different game build. `BattlEye monitor off: ...` means the crash guard is
working but the monitor isn't.

## Monitoring

| File | What it is |
|---|---|
| `BattlEyeFix.log` | Human-readable log of everything |
| `BattlEyeFix.status.json` | Current state, rewritten every 5 seconds. Point a dashboard, a Discord bot or your site at it |
| `BattlEyeFix.events.jsonl` | One JSON object per line, one line per event. Easy to graph, alert on or share |

The main fields in `BattlEyeFix.status.json`:

| Field | Meaning |
|---|---|
| `battlEye` | `"healthy"` or `"degraded"` |
| `recheck` | whether the re-check is on |
| `counts.suspectedFalseKicks` | kicks that look like BattlEye's mistake |
| `counts.normalKicks` | every other BattlEye kick, carried out as normal |
| `counts.held`, `counts.reregistrations` | players held, and fresh checks requested |
| `counts.passedAfterRecheck`, `counts.gaveUp` | held players who passed in the end, and who ran out of time |
| `counts.joinChecksPassed` | players who passed BattlEye's join check |
| `lastDegradedUtcMs`, `lastRecoveredUtcMs` | when BattlEye last went bad, and came back |
| `recent` | the last 50 events |

The event `kind`s are `kick`, `suspected false kick`, `degraded`, `recovered`, `re-registered`,
`re-check passed` and `re-check gave up`. A suspected false kick looks like this:

```json
{"atUtcMs":1794643837000,"kind":"suspected false kick","player":0,"reason":"Client not responding","msSinceRegister":17375,"msSinceReply":500,"lastReplyBytes":926,"packets":14,"suspectedFalse":true}
```

## The re-check

### Turning it on

Create a file named `BattlEyeFix.recheck` next to `winmm.dll`. An empty file uses the defaults. To change them,
put `key=value` lines in it:

```
holdSeconds=1800
retrySeconds=30
```

Changes are picked up within 5 seconds. Delete the file to turn the re-check off again.

| Setting | Default | Meaning |
|---|---|---|
| `holdSeconds` | 1200 (20 min) | How long a player can be held before being kicked as normal |
| `retrySeconds` | 30 | Wait between taking a player off BattlEye and registering them again |
| `minReplyBytes` | 500 | How big the player's reply must be to count as "answered" (the join check reply is about 926 bytes) |
| `replyWindowMs` | 2000 | How soon before the kick the reply must have arrived |
| `firstCheckSeconds` | 90 | Only kicks this soon after a player registers with BattlEye count (the join check) |
| `degradedKicks` | 3 | Suspected false kicks needed to call BattlEye degraded... |
| `degradedWindowSeconds` | 600 | ...within this many seconds |
| `notify` | 1 | Set to 0 to not show held players a message |
| `hold` | 1 | Set to 0 to keep the file but turn holding off |

### What a held player sees

A message box titled **"BattlEye check failed on BattlEye's side"**, saying they won't be kicked for now and
that the server will ask BattlEye to check them again. They can keep playing. They aren't disconnected,
including when they're registered again.

### Pros

- Players aren't kicked for BattlEye's mistakes. In our test, a player was held through 6 rejected checks over
  5 minutes, passed the 7th once BattlEye recovered, and was never disconnected.
- Protection comes back by itself when BattlEye recovers: no rejoin needed.
- Only one specific kind of kick is held. Bans, "Corrupted Memory", other kick reasons and real timeouts (no
  reply) are carried out as normal.
- It's cheap: under a millisecond of game-thread time per step, a few times a minute per held player.
- It uses the game's own join and leave functions, and changes no BattlEye data.

### Cons and warnings

- **A held player isn't protected by BattlEye.** Until they pass a fresh check, BattlEye isn't watching them.
  Anyone who joins during an outage, including a cheater who happens to join then, gets up to `holdSeconds` of
  play without BattlEye. Keep `holdSeconds` as short as your community can live with, and watch held players if
  you have other tools.
- **It can't fix BattlEye.** If BattlEye stays broken longer than `holdSeconds`, players are still kicked in
  the end. On 14 November the longest bad window was about 90 minutes.
- **The trigger can in theory be faked.** A held kick needs a full-size reply from the player's BattlEye just
  before the kick. Simply blocking BattlEye doesn't produce that, so it isn't an easy loophole, but a determined
  cheater could try to imitate it. The time limit caps what they could get out of it.
- **It overrides BattlEye's decision on your server.** That's your call as the owner. Check whether your hosting
  agreement or Funcom's rules for your server type say anything about it.
- **It's reverse-engineered.** It's tied to one game build, and checks every address before use. A game update
  switches it off until it's updated.
- **It never kicks anyone by itself.** It only decides whether to carry out or hold a kick that BattlEye sends.
  If BattlEye's servers can't be reached at all, there's no verdict, so nobody is held or kicked because of this
  tool. A player being held simply stays connected until BattlEye answers. The `holdSeconds` limit is applied
  when the next false kick arrives, so it doesn't fire while BattlEye is silent. Timeouts the server's own
  BattlEye raises (such as "Query Timeout") aren't held. They're kicked as normal.
- **It doesn't save or replay old replies.** BattlEye's checks are encrypted and only valid once, so an old reply
  would be rejected, and resending it would look like tampering. The re-check asks BattlEye for a new check
  instead.

### What we recommend

- **Everyone:** install it for the crash guard and the monitor. They have no downside.
- **Turn the re-check on** if BattlEye outages are costing you players. Start with the default 20 minutes.
  `BattlEyeFix.status.json` and `BattlEyeFix.events.jsonl` show how often it actually helps.
- **Turn it off** (delete `BattlEyeFix.recheck`) if your server has a cheating problem that matters more to you
  than outage kicks.

## Options

Create an empty file next to `winmm.dll` with one of these names:

| File | Effect |
|---|---|
| `BattlEyeFix.recheck` | Turns the BattlEye re-check on (see above). Takes effect within 5 seconds. |
| `BattlEyeFix.notice-off` | No message box: kicks happen immediately. The crash fix stays on. Takes effect within a second. |
| `BattlEyeFix.disabled` | Turns the whole fix off at the next server start. |

## Uninstall

Stop the server, delete `winmm.dll` (and the `BattlEyeFix.*` files if you like), then start the server.

## When Funcom fixes it

Once Funcom ships a game update, this file switches itself off because the build no longer matches. Remove it
when convenient, or watch this repository for an update.

## For players who get kicked

A "Query Timeout" kick means BattlEye on the player's own PC stopped responding. It's usually fixed by:

1. Restarting the game.
2. Reinstalling BattlEye: close the game, open the Conan Exiles install folder, go to
   `ConanSandbox\Binaries\Win64\BattlEye`, run `Uninstall_BattlEye.bat`, then `Install_BattlEye.bat`.
3. Verifying the game files in Steam.
4. Making sure a firewall or antivirus isn't blocking BattlEye.

The [BattlEye Repair tool](https://github.com/DefinitelyNotASquid/Conan-Battleye-Fix) does all of this for
players.

**"Client not responding" a few seconds to a minute after joining, for lots of players at once,** is usually
BattlEye's own servers failing, not the player's PC (see [above](#2-battleyes-servers-kick-players-who-did-nothing-wrong)).
Reinstalling won't help with that. If your server runs this fix, `BattlEyeFix.status.json` shows
`"battlEye": "degraded"` when it's happening.

<img width="1201" height="684" alt="image" src="https://github.com/user-attachments/assets/d6848ae0-58d7-42fa-9b6f-300a68cadcca" />

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

The DLL is written to `out\winmm.dll`, and the script prints its SHA-256. Release builds are on the
[Releases](../../releases) page.
