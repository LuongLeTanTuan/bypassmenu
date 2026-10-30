/* QoSMetrics — Frida agent (no jailbreak), mirrors PxExtFFiBypass/Tweak.x
 *
 *   frida -U -f com.garena.game.df -l agent.js --runtime=qjs
 *   frida -U com.garena.game.df -l agent.js          # attach, then reload UI
 *
 * Spawn mode is the reliable one: -[SKClient start] runs during PxExtFFi init,
 * before attach mode gets a chance to hook anything.
 */
'use strict';

const KEY = 'DF-0000-0000-0000-0000';
const UDID = '00008030-000A1B2C3D4E5F60';
const PRODUCT = 'com.garena.game.df';
const TOKEN = '0000000000000000000000000000000000000000000000000000000000000000';
const EXPIRES = '2100-01-01 00:00:00';
const EXPIRES_TS = 4102444800;

const NULL = ptr(0);
let installed = false;

const log = (s) => console.log('[QoSMetrics] ' + s);
const str = (s) => ObjC.classes.NSString.stringWithString_(s);
const safe = (fn, d) => { try { return fn(); } catch (e) { return d; } };

/* Read an IMP back after hooking. Frida's setter is silent on failure, so a
 * hook that never landed would otherwise look identical to one that did. */
function verify(cls, prefix, sel, expected) {
  try {
    const m = cls[prefix + ' ' + sel];
    if (!m) { log('VERIFY ' + prefix + sel + ' MISSING'); return false; }
    const got = m.implementation.toString();
    const ok = got === expected.toString();
    log('VERIFY ' + prefix + sel + ' ' + (ok ? 'OK' : 'MISMATCH'));
    return ok;
  } catch (e) {
    log('VERIFY ' + prefix + sel + ' ERROR ' + e);
    return false;
  }
}

/* Describe a value for the log without dumping user data wholesale. */
function describe(v) {
  if (!v || v.isNull()) return 'nil';
  try {
    const cls = v.$className;
    if (cls === 'NSString') {
      const s = v.toString();
      return 'NSString("' + (s.length > 80 ? s.slice(0, 80) + '…' : s) + '") len=' + s.length;
    }
    if (cls === 'NSNumber') return 'NSNumber(' + v.toString() + ')';
    if (cls === 'NSDate') return 'NSDate(' + v.toString() + ')';
    if (cls === 'NSDictionary') {
      const keys = safe(() => v.allKeys(), null);
      const n = safe(() => v.count(), 0);
      if (keys && n > 0 && n <= 12) {
        const names = [];
        for (let i = 0; i < n; i++) {
          const k = keys.objectAtIndex_(i);
          if (k.$className === 'NSString') names.push(k.toString());
        }
        return 'NSDictionary(' + n + ') keys=[' + names.join(',') + ']';
      }
      return 'NSDictionary(' + n + ')';
    }
    if (cls === 'NSArray') return 'NSArray(' + safe(() => v.count(), 0) + ')';
    return cls;
  } catch (e) {
    return '<unreadable>';
  }
}

/* Full state snapshot — this is what tells you why a bypass failed. */
function dumpState(client) {
  log('---- client state ----');
  const sels = ['savedKey', 'udidValue', 'token', 'sessionToken', 'resolvedToken',
                'expiryDate', 'expiredAtString', 'packageName', 'lastFailCode',
                'packagePayload', 'devicePayload', 'paidChallenge'];
  for (const sel of sels) {
    const v = call(client, sel, []);
    log('  ' + sel.padEnd(18) + ' = ' + describe(v));
  }
  const bools = ['hasValidatedSession', 'authWallRequired', 'validating',
                 'silentRevalidating', 'successCardShown', 'hideUI'];
  for (const sel of bools) {
    const v = call(client, sel, []);
    log('  ' + sel.padEnd(18) + ' = ' + (v ? 'YES' : 'NO'));
  }
  const pc = call(client, 'paidCount', []);
  log('  ' + 'paidCount'.padEnd(18) + ' = ' + pc);
}

function dumpEnvironment() {
  log('---- environment ----');
  log('pid      : ' + Process.id);
  log('arch     : ' + Process.arch);
  log('platform : ' + Process.platform);
  const imgs = Process.enumerateModules().filter(m =>
    /PxExt|QoSMetrics|DeltaForce/.test(m.name) || /substrate/i.test(m.name));
  log('---- load order ----');
  imgs.forEach(m => log('  ' + m.name + ' base=' + m.base + ' size=' + m.size));
  log('---- gate classes ----');
  const names = ['SKClient', 'SKStore', 'SKNetwork', 'SKUDIDFlow', 'SKHUD',
                 'SKOverlayVC', 'UIManager', 'MenuView', 'TPPFloatingButton',
                 'BypassEarlyLoader'];
  names.forEach(n => log('  ' + n.padEnd(18) + (ObjC.classes[n] ? 'present' : 'ABSENT')));
}

/* Hook an ObjC method. prefix is '-' or '+'. fn receives (self, orig, ...args).
 * Returns the original IMP, or null when the hook did not land. */
function hook(cls, prefix, sel, fn) {
  if (!cls) return null;
  const key = prefix + ' ' + sel;
  let method = null;
  try { method = cls[key]; } catch (e) { method = null; }
  if (!method) { log('INSTALL ' + key + ' MISSING'); return null; }
  const orig = method.implementation;
  const wrapper = function () {
    const args = [].slice.call(arguments);
    return fn.apply(null, [this, orig].concat(args));
  };
  method.implementation = wrapper;
  // Read it back: Frida's setter is silent, so verify rather than assume.
  const back = safe(() => cls[key].implementation, null);
  const ok = back && back.toString() === wrapper.toString();
  log('INSTALL ' + key + ' ' + (ok ? 'OK' : 'MISMATCH'));
  return orig;
}

/* Call a selector safely; returns undefined when absent. */
function call(obj, sel, args) {
  if (!obj || obj.isNull()) return undefined;
  return safe(() => obj[sel].apply(obj, args || []), undefined);
}

/* ------------------------------------------------------------- success path */

/* State only — no UI. The framework's own guards read these, so applying them
 * before the original code runs is what makes it take the licensed branch. */
function applyState(client) {
  if (!client || client.isNull()) return;
  call(client, 'setHasValidatedSession:', [1]);
  call(client, 'setAuthWallRequired:', [0]);
  call(client, 'setValidating:', [0]);
  call(client, 'setSilentRevalidating:', [0]);
  call(client, 'setSessionToken:', [str(TOKEN)]);
  call(client, 'setToken:', [str(TOKEN)]);
  call(client, 'setLastSubmittedKey:', [str(KEY)]);
  call(client, 'setExpiryDate:',
       [ObjC.classes.NSDate.dateWithTimeIntervalSince1970_(EXPIRES_TS)]);
  call(client, 'setPaidChallenge:', [str(TOKEN)]);
  call(client, 'setDevicePayload:', [ObjC.classes.NSDictionary.dictionary()]);
  call(client, 'setPackagePayload:', [ObjC.classes.NSDictionary.dictionary()]);
  call(client, 'setLastFailCode:', [NULL]);
}

/* The menu/overlay tree belongs to -[UIManager setupUI]. Nothing inside
 * PxExtFFi ever calls +[UIManager shared], and nothing outside it references
 * this UIManager class either, so the tree is dead code unless it is forced. */
function keyWindow() {
  const app = ObjC.classes.UIApplication.sharedApplication();
  let fallback = null;
  const scenes = safe(() => app.connectedScenes(), null);
  if (!scenes || scenes.isNull()) return safe(() => app.keyWindow(), null);
  const n = scenes.count();
  for (let i = 0; i < n; i++) {
    const s = scenes.objectAtIndex_(i);
    if (!safe(() => s.isKindOfClass_(ObjC.classes.UIWindowScene), 0)) continue;
    const wins = safe(() => s.windows(), null);
    if (!wins || wins.isNull()) continue;
    const m = wins.count();
    for (let j = 0; j < m; j++) {
      const w = wins.objectAtIndex_(j);
      if (!fallback) fallback = w;
      if (safe(() => w.isKeyWindow(), 0)) return w;
    }
  }
  return fallback || safe(() => app.keyWindow(), null);
}

function logView(label, v) {
  if (!v || v.isNull()) { log(label + ' = nil'); return; }
  log(label + ' ' + v.$className + ' hidden=' + safe(() => v.hidden(), '?') +
      ' alpha=' + safe(() => v.alpha(), '?') +
      ' frame=' + safe(() => JSON.stringify(v.frame()), '?') +
      ' super=' + describe(safe(() => v.superview(), null)) +
      ' win=' + describe(safe(() => v.window(), null)));
}

/* A view built before the key window existed has no window — it is sized,
 * exists, and is completely invisible. Parent it again. */
function attachToWindow(v, win, hide) {
  if (!win || !v || v.isNull()) return;
  const w = safe(() => v.window(), null);
  if (w && !w.isNull()) return;
  safe(() => win.addSubview_(v));
  safe(() => v.setHidden_(hide ? 1 : 0));
  log('UI: attached ' + v.$className);
}

/* setupUI builds the whole tree from scratch; a second call stacks a second
 * copy and orphans the first. Only ever force it once per process. */
let forcedSetupUI = false;

/* setupUI is 146 KB of obfuscated code that returns early — on device only the
 * TPP camera button appeared, and that one is built lazily by -showTPPButton:,
 * which we call ourselves. Both widgets are self-initialising constructors, so
 * build them directly when setupUI leaves them nil:
 *   +[MenuView menuWithFrame:]         -> -initWithFrame: , -setupUI
 *   +[FloatingButton buttonWithFrame:] -> +buttonWithType: , -setFrame: , -setup
 */
function buildMenuView(frame) {
  const mv = ObjC.classes.MenuView;
  if (!mv) { log('UI: MenuView absent'); return null; }
  return safe(() => mv.menuWithFrame_(frame), null);
}

function buildFloatButton(frame) {
  const fb = ObjC.classes.FloatingButton;
  if (!fb) { log('UI: FloatingButton absent'); return null; }
  return safe(() => fb.buttonWithFrame_(frame), null);
}

function winFrame(win) {
  const b = safe(() => win.bounds(), null);
  if (!b) return [0, 0, 390, 844];
  return [b.origin.x, b.origin.y, b.size.width, b.size.height];
}

function ensureUI() {
  const mgrCls = ObjC.classes.UIManager;
  if (!mgrCls) { log('UI: UIManager absent'); return; }
  const mgr = safe(() => mgrCls.shared(), null);
  if (!mgr || mgr.isNull()) { log('UI: shared nil'); return; }

  let menu = call(mgr, 'menu', []);
  let tpp = call(mgr, 'tppButton', []);
  log('UI: pass menu=' + describe(menu) + ' tpp=' + describe(tpp));

  if ((!menu || menu.isNull()) && (!tpp || tpp.isNull()) && !forcedSetupUI) {
    forcedSetupUI = true;
    log('UI: tree missing -> setupUI');
    call(mgr, 'setupUI', []);
    menu = call(mgr, 'menu', []);
    tpp = call(mgr, 'tppButton', []);
    log('UI: after setupUI menu=' + describe(menu) + ' tpp=' + describe(tpp));
  }

  /* Also builds the button when setupUI produced nothing, and un-hides one. */
  safe(() => mgr.showTPPButton_(1));
  if (safe(() => mgr.respondsToSelector_(ObjC.selector('updateTPPButtonState:')), 0))
    safe(() => mgr.updateTPPButtonState_(1));

  const win = keyWindow();
  log('UI: keyWindow=' + describe(win));

  /* setupUI bailed before creating the menu -> build one. MenuView fills itself
   * in -setupUI, including its own tab bar, so this is not an empty shell. */
  if ((!menu || menu.isNull()) && win && !win.isNull()) {
    menu = buildMenuView(winFrame(win));
    log('UI: built MenuView ' + describe(menu));
    if (menu && !menu.isNull()) safe(() => mgr.setMenu_(menu));
  }

  menu = call(mgr, 'menu', []);
  tpp = call(mgr, 'tppButton', []);
  const esp = call(mgr, 'espOverlay', []);
  logView('UI: menu', menu);
  logView('UI: tpp', tpp);
  logView('UI: esp', esp);

  if (tpp && !tpp.isNull()) {
    attachToWindow(tpp, win, false);
    safe(() => tpp.setHidden_(0));
    safe(() => tpp.setAlpha_(1));
    safe(() => tpp.setUserInteractionEnabled_(1));
  }
  if (menu && !menu.isNull()) attachToWindow(menu, win, true);
  if (esp && !esp.isNull()) attachToWindow(esp, win, true);

  /* The mod-menu handle is FloatingButton, a different class from the TPP
   * camera switch the player already sees. setupUI builds it then stores it via
   * -setFloatingButton: and wires its tap to -toggleMenu — but it returns
   * before that. Build it ourselves; -buttonWithFrame: already calls -setup. */
  let floatBtn = call(mgr, 'floatingButton', []);
  logView('UI: floatingButton', floatBtn);
  if ((!floatBtn || floatBtn.isNull()) && win && !win.isNull()) {
    floatBtn = buildFloatButton([16, 96, 56, 56]);
    log('UI: built FloatingButton ' + describe(floatBtn));
    if (floatBtn && !floatBtn.isNull()) safe(() => mgr.setFloatingButton_(floatBtn));
  }
  if (floatBtn && !floatBtn.isNull()) {
    attachToWindow(floatBtn, win, false);
    safe(() => floatBtn.setHidden_(0));
    safe(() => floatBtn.setAlpha_(1));
    safe(() => floatBtn.setUserInteractionEnabled_(1));
    if (safe(() => floatBtn.respondsToSelector_(ObjC.selector('makeDraggable')), 0))
      safe(() => floatBtn.makeDraggable());
    /* setupUI normally wires this; an absent onTap means the button is dead. */
    const onTap = safe(() => floatBtn.onTap(), null);
    if (!onTap || onTap.isNull()) {
      log('UI: floatingButton onTap was nil -> wiring toggleMenu');
      const blk = new ObjC.Block({
        retType: 'void',
        argTypes: [],
        implementation: () => safe(() => mgr.toggleMenu())
      });
      safe(() => floatBtn.setOnTap_(blk));
    }
  }
}

/* The three blocks the host registers through the C API
 * (apiclient_on_check_package / on_check_device / on_login). This is the exact
 * tail of -[SKClient handleResponse:error:]: package(token), device(device,
 * token), login(). Skipping any of them leaves the host's own post-login code —
 * the part that builds and enables its menu — never called. */
function fireCallbacks(client) {
  let token = call(client, 'sessionToken', []);
  if (!token || token.isNull()) token = ObjC.classes.NSString.stringWithString_('qos.token.synthetic');
  let device = call(client, 'devicePayload', []);
  if (!device || device.isNull()) device = ObjC.classes.NSDictionary.dictionary();

  const pkg = call(client, 'onCheckPackage', []);
  log('CALLBACK onCheckPackage=' + (pkg && !pkg.isNull() ? 'set' : 'nil'));
  if (pkg && !pkg.isNull()) safe(() => new ObjC.Block(pkg).implementation(token));

  const dev = call(client, 'onCheckDevice', []);
  log('CALLBACK onCheckDevice=' + (dev && !dev.isNull() ? 'set' : 'nil'));
  if (dev && !dev.isNull()) safe(() => new ObjC.Block(dev).implementation(device, token));

  const login = call(client, 'onLoginSuccess', []);
  log('CALLBACK onLoginSuccess=' + (login && !login.isNull() ? 'set' : 'nil'));
  if (login && !login.isNull()) safe(() => new ObjC.Block(login).implementation());
}

/* Nothing in PxExtFFi calls +[UIManager shared], so the framework tree only
 * appears if forced. A grant can land before the key window exists, so run a
 * handful of passes instead of guessing one moment. */
function ensureUILater() {
  [500, 1500, 3000, 6000, 10000].forEach(ms => setTimeout(() => safe(() => ensureUI()), ms));
}

function grant(client) {
  if (!client || client.isNull()) { log('GRANT aborted: client nil'); return; }
  log('GRANT begin');
  dumpState(client);
  applyState(client);

  // Callback order follows the framework: host builds its UI from these, then
  // pending blocks run.
  fireCallbacks(client);
  call(client, 'runPendingBlocks', []);

  const hud = call(client, 'hud', []);
  call(hud, 'hideLoading', []);
  call(hud, 'hideBlockingWait', []);

  ensureUILater();

  // A prompt left up keeps SKHUD's shield in the host view, which covers the
  // menu and eats touches.
  call(hud, 'dismissAll', []);
  call(hud, 'dropShieldIfIdle', []);
  log('GRANT overlay cleared visible=' + safe(() => hud.hasVisibleHUD(), '?'));

  log('GRANT done');
  dumpState(client);
}

function grantAsync(client) {
  // Let the caller's stack unwind first — same ordering the original uses
  // between its async network callback and its main-thread UI mutation.
  setTimeout(() => safe(() => grant(client)), 250);
}

/* ------------------------------------------------------------------ install */

function install() {
  if (installed) return;
  const SKStore = ObjC.classes.SKStore;
  const SKClient = ObjC.classes.SKClient;
  if (!SKStore || !SKClient) return;
  installed = true;

  const SKNetwork = ObjC.classes.SKNetwork;
  const SKUDIDFlow = ObjC.classes.SKUDIDFlow;
  const SKHUD = ObjC.classes.SKHUD;
  const storeMeta = SKStore.class;

  /* SKStore — every read answers the shim, every write is dropped. */
  hook(storeMeta, '+', 'boundKey', function () { return str(KEY); });
  hook(storeMeta, '+', 'savedUDID', function () { return str(UDID); });
  hook(storeMeta, '+', 'savedDeviceName', function () { return str('iPhone'); });
  hook(storeMeta, '+', 'savedProduct', function () { return str(PRODUCT); });
  hook(storeMeta, '+', 'saveKey:forUDID:', function () {});
  hook(storeMeta, '+', 'saveUDID:deviceName:product:', function () {});
  hook(storeMeta, '+', 'clearSavedKey', function () {});
  hook(storeMeta, '+', 'clearUDID', function () {});

  /* SKNetwork — never dispatch the HMAC + TLS-pinned request. */
  hook(SKNetwork ? SKNetwork.class : null, '+', 'signedCheck:extraQuery:completion:',
    function (self, orig, payload, query, completion) {
      log('signedCheck short-circuited');
      if (!completion || completion.isNull()) return;
      const env = ObjC.classes.NSDictionary.dictionaryWithObjectsForKeys_(
        [ptr(1), ptr(1), str(KEY), str(UDID), str(PRODUCT), str(TOKEN), str(EXPIRES)],
        [str('ok'), str('valid'), str('key'), str('udid'), str('product'),
         str('token'), str('expires_at')]);
      const blk = new ObjC.Block(completion);
      setTimeout(() => safe(() => blk.implementation(env, ptr(0))), 50);
    });

  /* SKUDIDFlow — no mobileconfig, no udid-callback, no polling. */
  hook(SKUDIDFlow ? SKUDIDFlow.class : null, '+', 'installOpenURLHook', function (self, orig) {
    log('openURL swizzle skipped');
  });
  hook(SKUDIDFlow, '-', 'handleOpenURL:', function (self, orig, url) {
    log('udid callback ignored');
    return 0;
  });
  hook(SKUDIDFlow, '-', 'startCaptureWithReady:', function (self, orig, ready) {
    log('udid capture skipped');
    if (!ready || ready.isNull()) return;
    const blk = new ObjC.Block(ready);
    setTimeout(() => safe(() => blk.implementation()), 50);
  });
  hook(SKUDIDFlow, '-', 'startPolling', () => {});
  hook(SKUDIDFlow, '-', 'stopPolling', () => {});
  hook(SKUDIDFlow, '-', 'pollOnce', () => {});
  hook(SKUDIDFlow, '-', 'appDidBecomeActive', () => {});
  hook(SKUDIDFlow, '-', 'hasUDID', () => 1);
  hook(SKUDIDFlow, '-', 'currentUDID', () => str(UDID));
  hook(SKUDIDFlow, '-', 'finishWithUDID:name:product:', () => {
    log('finishWithUDID suppressed');
  });

  /* SKClient — the state machine. */
  hook(SKClient, '-', 'savedKey', function () { return str(KEY); });
  hook(SKClient, '-', 'udidValue', function () { return str(UDID); });
  hook(SKClient, '-', 'token', function () { return str(TOKEN); });
  hook(SKClient, '-', 'resolvedToken', function () { return str(TOKEN); });
  hook(SKClient, '-', 'expiredAtString', function () { return str(EXPIRES); });
  hook(SKClient, '-', 'expiredAtLocalString', function () { return str(EXPIRES); });
  hook(SKClient, '-', 'expiryDate', function () {
    return ObjC.classes.NSDate.dateWithTimeIntervalSince1970_(EXPIRES_TS);
  });
  hook(SKClient, '-', 'hasValidatedSession', function () { return 1; });
  hook(SKClient, '-', 'authWallRequired', function () { return 0; });

  hook(SKClient, '-', 'validateWithKey:showUI:', function (self, orig, key, showUI) {
    log('validateWithKey showUI=' + showUI);
    const k = (key && !key.isNull()) ? key : str(KEY);
    call(self, 'setLastSubmittedKey:', [k]);
    grantAsync(self);
  });
  hook(SKClient, '-', 'ensureThenValidate', function (self) { grantAsync(self); });
  hook(SKClient, '-', 'continueAfterUDID', function (self) { grantAsync(self); });

  // Keep the original: it owns the overlay/window plumbing the HUD renders into.
  // State goes in first — -start reads it through -uiAllowed and bails out of
  // the licensed branch when it is not set, which is how the menu disappears.
  hook(SKClient, '-', 'start', function (self, orig) {
    log('start -> applying state, then original');
    safe(() => applyState(self));
    safe(() => orig());
    grantAsync(self);
  });

  /* -uiAllowed is the single question the framework asks before showing
   * anything, and -hideUI is the flag it consults. */
  hook(SKClient, '-', 'uiAllowed', function (self, orig) {
    const real = safe(() => orig(), 0);
    log('uiAllowed -> YES (real=' + real + ')');
    return 1;
  });
  hook(SKClient, '-', 'hideUI', function (self, orig) {
    const real = safe(() => orig(), 0);
    log('hideUI -> NO (real=' + real + ')');
    return 0;
  });

  /* Observation only: these answer "who builds the menu, and does the framework
   * ever reach it on its own". */
  const UIManager = ObjC.classes.UIManager;
  if (UIManager) {
    hook(UIManager, '-', 'teardownUI', function () { log('teardownUI blocked'); });
    hook(UIManager, '-', 'setupUI', function (self, orig) {
      log('HOOK -setupUI enter');
      safe(() => orig());
      logView('HOOK setupUI menu', call(self, 'menu', []));
      logView('HOOK setupUI tpp', call(self, 'tppButton', []));
    });
    hook(UIManager, '-', 'showTPPButton:', function (self, orig, on) {
      log('HOOK -showTPPButton:' + on);
      safe(() => orig());
      logView('HOOK showTPP tpp', call(self, 'tppButton', []));
    });
    hook(UIManager, '-', 'toggleMenu', function (self, orig) {
      log('HOOK -toggleMenu');
      safe(() => orig());
      logView('HOOK toggleMenu menu', call(self, 'menu', []));
    });
  }

  hook(SKClient, '-', 'fail:code:silent:', function (self, orig, a, code, silent) {
    log('fail swallowed ' + (code && !code.isNull() ? code.toString() : '?'));
  });
  hook(SKClient, '-', 'revalidateTick', function () {});
  hook(SKClient, '-', 'scheduleRevalidate', function () {});
  hook(SKClient, '-', 'handleKeyFailureWithCode:message:', function () {});
  hook(SKClient, '-', 'promptForNewKeyWithMessage:', function () {});
  hook(SKClient, '-', 'submitKey:', function (self) { grantAsync(self); });
  hook(SKClient, '-', 'isFatalCode:', function () { return 0; });
  hook(SKClient, '-', 'isKeyErrorCode:', function () { return 0; });
  hook(SKClient, '-', 'enforceLock', function () {});

  /* SKHUD — nothing gates on screen. */
  hook(SKHUD, '-', 'showUDIDPrompt:guide:', function () {});
  hook(SKHUD, '-', 'showKeyPrompt:onSubmit:', function () {});
  hook(SKHUD, '-', 'showFatalNotice:message:', function (self, orig, t) {
    log('fatal suppressed ' + (t && !t.isNull() ? t.toString() : '?'));
  });
  hook(SKHUD, '-', 'showNotice:message:', function () {});
  hook(SKHUD, '-', 'showBlockingWait:message:actionTitle:onAction:', function () {});

  log('installed');
  dumpEnvironment();

  const shared = safe(() => SKClient.shared(), null);
  if (shared && !shared.isNull()) applyState(shared);
}

/* PxExtFFi may not be mapped yet at attach time: poll, bounded. */
let attempts = 0;
const timer = setInterval(() => {
  if (!ObjC.classes.SKClient && attempts % 10 === 0) {
    log('WAIT attempt ' + attempts + ': SKClient not mapped yet');
  }
  safe(install);
  if (installed || ++attempts > 120) {
    clearInterval(timer);
    if (!installed) log('GIVE UP after ' + attempts + ' attempts');
  }
}, 250);

/* -[UIManager toggleMenu] is what puts MenuView on screen: it does the
 * addSubview:/removeFromSuperview itself, and it is what -[FloatingButton
 * buttonTapped] reaches through its onTap block. */
function showMenu() {
  const mgrCls = ObjC.classes.UIManager;
  if (!mgrCls) { log('MENU: UIManager absent'); return; }
  const mgr = safe(() => mgrCls.shared(), null);
  if (!mgr || mgr.isNull()) { log('MENU: shared nil'); return; }
  if (!call(mgr, 'menu', [])) {
    log('MENU: no MenuView yet -> building one');
    const win = keyWindow();
    if (win && !win.isNull()) {
      const m = buildMenuView(winFrame(win));
      if (m && !m.isNull()) safe(() => mgr.setMenu_(m));
    }
  }
  const menu = call(mgr, 'menu', []);
  const win = keyWindow();
  if (menu && !menu.isNull()) attachToWindow(menu, win, false);
  log('MENU: toggleMenu');
  call(mgr, 'toggleMenu', []);
  logView('MENU: menu after toggle', call(mgr, 'menu', []));
}

/* Live diagnostics — type these in the Frida REPL once attached.
 *
 *   qos()        full state dump
 *   qosenv()     modules, load order, class presence
 *   qosgrant()   force a grant right now
 *   qosmenu()    open/close the mod menu
 *   qoshelp()    this list
 */
globalThis.qos = () => {
  const c = safe(() => ObjC.classes.SKClient.shared(), null);
  dumpState(c);
  return 'ok';
};
globalThis.qosenv = () => { dumpEnvironment(); return 'ok'; };
globalThis.qosgrant = () => {
  const c = safe(() => ObjC.classes.SKClient.shared(), null);
  grant(c);
  return 'ok';
};
globalThis.qosmenu = () => { showMenu(); return 'ok'; };
globalThis.qoshelp = () => {
  ['qos()      - dump SKClient state',
   'qosenv()   - dump modules / load order / classes',
   'qosgrant() - force grant now',
   'qosmenu()  - open/close the mod menu',
   'qoshelp()  - this list'].forEach(log);
  return 'ok';
};

log('agent loaded pid=' + Process.id);
log('repl: qoshelp() for diagnostics');
