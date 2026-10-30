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

/* Hook an ObjC method. prefix is '-' or '+'. fn receives (self, orig, ...args). */
function hook(cls, prefix, sel, fn) {
  if (!cls) return null;
  const key = prefix + ' ' + sel;
  let method = null;
  try { method = cls[key]; } catch (e) { method = null; }
  if (!method) { log('missing ' + key); return null; }
  const orig = method.implementation;
  method.implementation = function () {
    const args = [].slice.call(arguments);
    return fn.apply(null, [this, orig].concat(args));
  };
  return orig;
}

/* Call a selector safely; returns undefined when absent. */
function call(obj, sel, args) {
  if (!obj || obj.isNull()) return undefined;
  return safe(() => obj[sel].apply(obj, args || []), undefined);
}

/* ------------------------------------------------------------- success path */

function grant(client) {
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
  // handleResponse: also sets these. MenuView/ModSkinView/ESPOverlayView read
  // packagePayload for every feature key (slot0_weapon, melee_skin, ...) — nil
  // there unlocks the shell but renders an empty menu.
  call(client, 'setPaidChallenge:', [str(TOKEN)]);
  call(client, 'setDevicePayload:', [ObjC.classes.NSDictionary.dictionary()]);
  call(client, 'setPackagePayload:', [ObjC.classes.NSDictionary.dictionary()]);
  call(client, 'setLastFailCode:', [NULL]);
  call(client, 'runPendingBlocks', []);

  const hud = call(client, 'hud', []);
  call(hud, 'hideLoading', []);
  call(hud, 'hideBlockingWait', []);

  const mgrCls = ObjC.classes.UIManager;
  if (mgrCls) {
    const mgr = safe(() => mgrCls.shared(), null);
    call(mgr, 'setupUI', []);
    call(mgr, 'showTPPButton:', [1]);
  }

  const cb = call(client, 'onLoginSuccess', []);
  if (cb && !cb.isNull()) safe(() => new ObjC.Block(cb).implementation());

  log('granted');
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
  // Its network and UDID calls are already inert by the time it runs.
  hook(SKClient, '-', 'start', function (self, orig) {
    safe(() => orig());
    grantAsync(self);
  });

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

  const shared = safe(() => SKClient.shared(), null);
  if (shared && !shared.isNull()) grant(shared);
}

/* PxExtFFi may not be mapped yet at attach time: poll, bounded. */
let attempts = 0;
const timer = setInterval(() => {
  safe(install);
  if (installed || ++attempts > 120) clearInterval(timer);
}, 250);

log('agent loaded pid=' + Process.id);
