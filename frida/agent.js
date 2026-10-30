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

/* The menu/overlay tree belongs to -[UIManager setupUI]. Forcing it a second
 * time builds a duplicate and orphans the first, so only call it when the tree
 * is genuinely missing; re-attach a button built before the window existed. */
function ensureUI() {
  const mgrCls = ObjC.classes.UIManager;
  if (!mgrCls) { log('UI: UIManager absent'); return; }
  const mgr = safe(() => mgrCls.shared(), null);
  if (!mgr || mgr.isNull()) { log('UI: shared nil'); return; }

  let menu = call(mgr, 'menu', []);
  let tpp = call(mgr, 'tppButton', []);
  log('UI: before menu=' + describe(menu) + ' tpp=' + describe(tpp));

  if ((!menu || menu.isNull()) && (!tpp || tpp.isNull())) {
    log('UI: menu missing -> forcing setupUI');
    call(mgr, 'setupUI', []);
    call(mgr, 'showTPPButton:', [1]);
    menu = call(mgr, 'menu', []);
    tpp = call(mgr, 'tppButton', []);
    log('UI: after setupUI menu=' + describe(menu) + ' tpp=' + describe(tpp));
  }

  if (tpp && !tpp.isNull()) {
    const win = safe(() => tpp.window(), null);
    if (!win || win.isNull()) {
      const keyWin = safe(() => ObjC.classes.UIApplication.sharedApplication()
        .keyWindow(), null);
      log('UI: tpp has no window, keyWindow=' + describe(keyWin));
      if (keyWin && !keyWin.isNull()) safe(() => keyWin.addSubview_(tpp));
    } else {
      log('UI: tpp attached hidden=' + safe(() => tpp.hidden(), '?') +
          ' alpha=' + safe(() => tpp.alpha(), '?'));
    }
  }
}

function grant(client) {
  if (!client || client.isNull()) { log('GRANT aborted: client nil'); return; }
  log('GRANT begin');
  dumpState(client);
  applyState(client);
  call(client, 'runPendingBlocks', []);

  const hud = call(client, 'hud', []);
  call(hud, 'hideLoading', []);
  call(hud, 'hideBlockingWait', []);

  ensureUI();

  const cb = call(client, 'onLoginSuccess', []);
  if (cb && !cb.isNull()) {
    log('GRANT firing onLoginSuccess');
    safe(() => new ObjC.Block(cb).implementation());
  } else {
    log('GRANT no onLoginSuccess callback');
  }
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

  /* Teardown removes the menu tree. The env scanner and the revocation tick
   * both route here; a menu that vanishes seconds after appearing is the
   * visible symptom. */
  const UIManager = ObjC.classes.UIManager;
  if (UIManager) {
    hook(UIManager, '-', 'teardownUI', function () { log('teardownUI blocked'); });
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

/* Live diagnostics — type these in the Frida REPL once attached.
 *
 *   qos()        full state dump
 *   qosenv()     modules, load order, class presence
 *   qosgrant()   force a grant right now
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
globalThis.qoshelp = () => {
  ['qos()      - dump SKClient state',
   'qosenv()   - dump modules / load order / classes',
   'qosgrant() - force grant now',
   'qoshelp()  - this list'].forEach(log);
  return 'ok';
};

log('agent loaded pid=' + Process.id);
log('repl: qoshelp() for diagnostics');
