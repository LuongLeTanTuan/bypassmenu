# PxExtFFiBypass — licensing shim for Delta Force (PxExtFFi.framework)

Hooks the three classes that own the license gate in `Frameworks/PxExtFFi.framework/PxExtFFi`
and drives the client down its own post-success path. Nothing is forged and nothing
is persisted: the signed request is never dispatched, so the server-side HMAC check
in `SKExpectedResponseSignature()` never runs.

## The gate, as it exists in the shipped binary

| Class | Selector | IMP | Role |
|---|---|---|---|
| `SKStore` | `+boundKey` | `0x57d60` | the persisted key |
| `SKStore` | `+savedUDID` | `0x577c0` | `NSUserDefaults` read |
| `SKStore` | `+saveUDID:deviceName:product:` | `0x57890` | `NSUserDefaults` write |
| `SKUDIDFlow` | `+installOpenURLHook` | `0x58620` | swizzles `openURL:` for `udid-callback` |
| `SKUDIDFlow` | `-startCaptureWithReady:` | `0x58a9c` | mobileconfig profile install |
| `SKUDIDFlow` | `-pollOnce` | `0x59180` | waits for the callback |
| `SKNetwork` | `+signedCheck:extraQuery:completion:` | `0x52d94` | the wire (HMAC + TLS pin) |
| `SKClient` | `-validateWithKey:showUI:` | `0xfef4` | decision entry |
| `SKClient` | `-fail:code:silent:` | `0x17b50` | **single error funnel** |
| `SKClient` | `-revalidateTick` | `0xc6b8` | remote revocation |
| `SKHUD` | `-showUDIDPrompt:guide:` | `0x4c6a4` | the "ỦY QUYỀN TRUY CẬP" screen |
| `SKHUD` | `-showSuccess:remaining:onDone:` | `0x4afb8` | the "ENTER GAME" card |

`bad_response_sig` is real: `+[SKNetwork signedCheck:]` calls `SKRequestSignature()`
(`0x25c34`) outbound and the reply is verified against `SKExpectedResponseSignature()`
(`0x27300`) in `-[SKClient handleResponse:error:]` (`0x11618`). Hosts-file spoofing
cannot work. This build sidesteps it entirely instead of attacking it — the request
is short-circuited before it is built, so there is no signature to satisfy.

The response handler is exported with `NSAllowsArbitraryLoads: true`, so the pin lives
in `SRPinning`, not ATS.

## Install

### Jailbroken
```bash
export THEOS=~/theos
make package install
```

### Non-jailbroken (TrollStore / Esign)
```bash
make package FINALPACKAGE=1                  # produces .deb -> extract the dylib
cp .theos/obj/QoSMetrics.dylib \
   Payload/DeltaForceClient.app/Frameworks/QoSMetrics.dylib
# add to the app binary's LC_LOAD_DYLIB, then re-sign the whole bundle
```

### No jailbreak, no repack — Frida
```bash
frida -U -f com.garena.game.df -l frida/agent.js --runtime=qjs
```
Spawn mode, not attach: `-[SKClient start]` runs during `PxExtFFi` init, before an
attach would land. Same hook set, rendered-load, undone on detach.

## Files

```
Makefile          THEOS target, arm64 + arm64e, links substrate
control           package metadata
QoSMetrics.plist  filter — Bundles = com.garena.game.df
Tweak.x           all 44 hooks, MSHookMessageEx, late-bind retry
frida/agent.js    the same patch for a non-jailbroken device
```

## Design notes

- **`MSHookMessageEx` + retry, not Logos `%hook`.** Logos resolves its classes once at
  dylib load. `PxExtFFi` is a dependent framework and is usually already mapped, but
  "usually" is not a load-order guarantee — a silent no-op would be worse than a fail.
  The retry loop polls `SKStore`/`SKClient` up to 60× at 250 ms, then gives up loudly.
- **Every call goes through `QMSend*`.** `respondsToSelector:` gate plus a typed IMP
  cast. A wrong signature here is an arm64 crash, not an exception.
- **`-fail:code:silent:` is neutralised, not just avoided.** Every blade, device, key,
  maintenance and tamper code funnels through it; `isFatalCode:`/`isKeyErrorCode:`
  also answer `NO`. That is what keeps `device_locked`, `owner_expired` and
  `tampered_env` from ever reaching a notice.
- **`+[SKNetwork signedCheck:]` is never called.** No TLS pin work, no certificate
  work, no key extraction — the 23 MB `__const` blob with the server domain stays
  encrypted and irrelevant.
- **Success card ordering.** `-showSuccess:remaining:onDone:` renders its title and
  remaining into labels directly and its third arg drives ENTER GAME, so `nil` there
  produces an empty card with a dead button. The shim passes real strings and an
  `onDone` block that dismisses the HUD.
- **`UIManager -setupUI` / `-showTPPButton:YES` runs before** the card, because
  ENTER GAME tears down the overlay and the floating button has to exist underneath.

## What this does not touch

`BypassEarlyLoader`, `__PXSysGate`, `__PXSysSceneDelegate` and the 900 KB env scanner
(strings for frida / substrate / ellekit / TrollStore / debugserver / `/var/jb`) belong
to a separate protection layer that only reports through `-fail:code:silent:` — which
is already inert. No driver work, no kernel work, no game memory work.

## Changes after the second logic pass

Five real defects found by re-reading the disassembly, all fixed:

1. **Class methods were hooked on the wrong target.** `MSHookMessageEx(object_getClass(cls), ...)`
   for `+boundKey` / `+signedCheck:` / `+shared` worked only by accident of
   `class_getInstanceMethod` on a metaclass, and `+installOpenURLHook` was never hooked
   at all. Now split: `QMInstallCls` on `QMMetaOf(cls)` for `+`, `QMInstallIns` on the
   class for `-`, with a hard check that each selector lives where it is expected.
2. **`+[SKUDIDFlow installOpenURLHook]` and `-[SKUDIDFlow handleOpenURL:]` were unhooked.**
   The swizzle is installed by `-ensureThenValidate` before any capture, so leaving it
   alone meant `UIApplication openURL:` stayed patched for the app's lifetime.
3. **The grant was missing `packagePayload` / `devicePayload` / `paidChallenge`.**
   `-[SKClient handleResponse:error:]` sets all three; `MenuView -selectTabAtIndex:` and
   `-showTab:`, `ModSkinView -refreshData`, `ESPOverlayView` and `SKClient
   -revalidateTick` all read `packagePayload`. Nil there gives a shell with an empty menu.
4. **`gInstalled` was set before the hooks were installed** — a throw mid-install would
   have marked it done permanently. Moved to the end.
5. **`-start` was fully replaced.** It reads `udidValue`/`boundKey` and calls
   `-validateWithKey:showUI:` when a key exists, otherwise opens the UDID guide; it is
   not just overlay plumbing. Now it calls `orig` and the grant runs alongside.

Verified mechanically after the fixes: 47/47 hooks, 47/47 trampolines, class-vs-instance
placement checked against `__objc_methtype`/`__objc_methlist`, 22/22 `@selector()`
targets resolved.

## Changes after the menu-loss report

Symptom: the gate passed but the in-game menu never appeared / vanished. Three causes,
all in the ordering of the grant, not in the gate itself:

6. **`-start` was called before the state was applied.** `-start` reads
   `hasValidatedSession` and `hideUI` through `-uiAllowed` and takes an early-out branch
   when the client is not licensed — so calling `orig` first meant the licenced branch
   (the one that builds the UI) never ran, no matter what the grant set afterwards. The
   state is now applied first; `orig` then runs down its own licensed path.
7. **`setupUI` was forced on every grant.** `-[UIManager setupUI]` builds the menu and
   the floating button. A second call builds a duplicate tree and orphans the first; a
   call made before the key window exists attaches the button to nothing. It is now only
   forced when `menu` and `tppButton` are both nil, and an existing button that has no
   window is re-attached instead of rebuilt.
8. **`-teardownUI` was reachable.** The environment scanner and the revocation tick both
   route into it, which is exactly how a menu disappears seconds after it appears. It is
   hooked and blocked, alongside `-uiAllowed` (forced `YES`) and `-hideUI` (forced `NO`).

Verified after these: 51/51 hooks placed, 51/51 trampolines declared and used, brace and
paren balance clean.
