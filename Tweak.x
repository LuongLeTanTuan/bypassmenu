// QoSMetrics — runtime licensing shim for PxExtFFi.framework (Garena Delta Force)
//
// Gate ownership, resolved from the shipped Mach-O:
//   +[SKStore boundKey]                                  0x57d60
//   +[SKStore savedUDID] / -saveUDID:deviceName:product:  0x577c0 / 0x57890
//   +[SKUDIDFlow installOpenURLHook]                      0x58620
//   -[SKUDIDFlow startCaptureWithReady:] / -pollOnce      0x58a9c / 0x59180
//   +[SKNetwork signedCheck:extraQuery:completion:]        0x52d94   (HMAC + TLS pin)
//   -[SKClient validateWithKey:showUI:]                    0xfef4
//   -[SKClient fail:code:silent:]                          0x17b50  (single funnel)
//   -[SKClient revalidateTick] / -scheduleRevalidate       0xc6b8 / 0xc608
//   -[SKHUD showUDIDPrompt:guide:]                         0x4c6a4
//
// Strategy: short-circuit at the state machine, never at the wire. The response
// envelope is signed server-side and verified in SKExpectedResponseSignature(),
// so nothing is forged — the request is simply never dispatched, and the client
// is driven down its own post-success path.
//
// Hooking is done with MSHookMessageEx + a retry loop rather than Logos %hook:
// Logos binds its classes exactly once at dylib load, and PxExtFFi may not be
// mapped yet at that moment, which would leave every hook silently uninstalled.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <unistd.h>
#import <mach-o/dyld.h>

#import "QMDiag.h"

#define LOG(fmt, ...) QMDiagLog(fmt, ##__VA_ARGS__)

static NSString *const kSyntheticKey = @"DF-0000-0000-0000-0000";
static NSString *const kSyntheticUDID = @"00008030-000A1B2C3D4E5F60";
static NSString *const kSyntheticProduct = @"com.garena.game.df";
static NSString *const kSyntheticToken =
    @"0000000000000000000000000000000000000000000000000000000000000000";

#pragma mark - Safe message dispatch

static id QMSend0(id t, SEL s) {
    if (!t || ![t respondsToSelector:s]) return nil;
    return ((id (*)(id, SEL))[t methodForSelector:s])(t, s);
}
static void QMSendV(id t, SEL s) {
    if (!t || ![t respondsToSelector:s]) return;
    ((void (*)(id, SEL))[t methodForSelector:s])(t, s);
}
static void QMSendO(id t, SEL s, id a) {
    if (!t || ![t respondsToSelector:s]) return;
    ((void (*)(id, SEL, id))[t methodForSelector:s])(t, s, a);
}
static void QMSendB(id t, SEL s, BOOL a) {
    if (!t || ![t respondsToSelector:s]) return;
    ((void (*)(id, SEL, BOOL))[t methodForSelector:s])(t, s, a);
}
static void QMSendOOO(id t, SEL s, id a, id b, id c) {
    if (!t || ![t respondsToSelector:s]) return;
    ((void (*)(id, SEL, id, id, id))[t methodForSelector:s])(t, s, a, b, c);
}

#pragma mark - Success path (mirrors -[SKClient handleResponse:error:] tail)

// handleResponse: sets devicePayload/packagePayload/paidChallenge/paidCount/
// sessionToken before firing onCheckPackage/onCheckDevice/onLoginSuccess.
// MenuView, ModSkinView and ESPOverlayView all read packagePayload (its keys are
// slot0_weapon, slot0_skin, melee_weapon, costume_hero, ...), so a grant that
// leaves it nil unlocks the shell but renders an empty menu. Empty dictionary is
// enough to iterate: every lookup returns nil and the views fall back to defaults.
static NSDictionary *QMPackagePayload(void) {
    static NSDictionary *payload;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ payload = @{}; });
    return payload;
}

static void QMGrant(id client, BOOL showCard) {
    if (!client) {
        LOG(@"GRANT aborted: client is nil");
        return;
    }
    LOG(@"GRANT begin showCard=%d", (int)showCard);
    QMDiagDumpState(client);

    QMSendB(client, @selector(setHasValidatedSession:), YES);
    QMSendB(client, @selector(setAuthWallRequired:), NO);
    QMSendB(client, @selector(setValidating:), NO);
    QMSendB(client, @selector(setSilentRevalidating:), NO);
    QMSendO(client, @selector(setSessionToken:), kSyntheticToken);
    QMSendO(client, @selector(setToken:), kSyntheticToken);
    QMSendO(client, @selector(setLastSubmittedKey:), kSyntheticKey);
    QMSendO(client, @selector(setExpiryDate:),
            [NSDate dateWithTimeIntervalSince1970:4102444800.0]);  // 2100-01-01
    QMSendO(client, @selector(setPaidChallenge:), kSyntheticToken);
    QMSendO(client, @selector(setDevicePayload:), @{});
    QMSendO(client, @selector(setPackagePayload:), QMPackagePayload());
    QMSendO(client, @selector(setLastFailCode:), nil);
    QMSendV(client, @selector(runPendingBlocks));

    id hud = QMSend0(client, @selector(hud));
    QMSendV(hud, @selector(hideLoading));
    QMSendV(hud, @selector(hideBlockingWait));

    // Unlock the in-game surface first: the success card's ENTER GAME handler
    // tears the overlay down, so the button must already exist underneath it.
    Class mgr = NSClassFromString(@"UIManager");
    id shared = QMSend0((id)mgr, @selector(shared));
    QMSendV(shared, @selector(setupUI));
    QMSendB(shared, @selector(showTPPButton:), YES);

    if (showCard) {
        QMSendB(client, @selector(setSuccessCardShown:), YES);
        // title/remaining are rendered straight into labels; done drives ENTER GAME.
        void (^onDone)(void) = ^{
            QMSendV(hud, @selector(dismissAll));
            LOG(@"enter game");
        };
        QMSendOOO(hud, @selector(showSuccess:remaining:onDone:),
                  @"ACTIVATION SUCCESSFUL", @"Unlimited", onDone);
    }

    id cb = QMSend0(client, @selector(onLoginSuccess));
    if (cb) {
        LOG(@"GRANT firing onLoginSuccess");
        ((void (^)(void))cb)();
    } else {
        LOG(@"GRANT no onLoginSuccess callback set");
    }

    LOG(@"GRANT done");
    QMDiagDumpState(client);
}

static void QMGrantAsync(id client, BOOL showCard) {
    // The original mutates UI on the main thread after its async callback;
    // keep the same ordering so SKHUD's view tree exists.
    LOG(@"GRANT scheduled showCard=%d in 250ms", (int)showCard);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ QMGrant(client, showCard); });
}

#pragma mark - Method plumbing

// Instance methods are hooked on the class; class methods on the metaclass.
static Class QMMetaOf(Class cls) {
    return cls ? object_getClass(cls) : Nil;
}

static void QMInstallCls(Class cls, const char *name, IMP hook, IMP *orig) {
    if (!cls || !name) {
        LOG(@"INSTALL %-46s SKIPPED (no class)", name ? name : "(null)");
        return;
    }
    SEL sel = sel_registerName(name);
    if (!class_getInstanceMethod(cls, sel)) {
        LOG(@"INSTALL %-46s MISSING on %s", name, class_getName(cls));
        return;
    }
    MSHookMessageEx(cls, sel, hook, orig);
    // MSHookMessageEx returns void: read the IMP back to learn the truth.
    QMDiagVerifyHook(cls, sel, hook, name);
}

static void QMInstallIns(Class cls, const char *name, IMP hook, IMP *orig) {
    QMInstallCls(cls, name, hook, orig);
}

static BOOL gInstalled = NO;

#pragma mark - SKStore — coherent identity, no server binding

static id (*origStoreBoundKey)(id, SEL);
static id QMHookStoreBoundKey(id self, SEL _cmd) { return kSyntheticKey; }

static id (*origStoreSavedUDID)(id, SEL);
static id QMHookStoreSavedUDID(id self, SEL _cmd) { return kSyntheticUDID; }

static id (*origStoreSavedDeviceName)(id, SEL);
static id QMHookStoreSavedDeviceName(id self, SEL _cmd) { return @"iPhone"; }

static id (*origStoreSavedProduct)(id, SEL);
static id QMHookStoreSavedProduct(id self, SEL _cmd) { return kSyntheticProduct; }

static void (*origSaveKey)(id, SEL, id, id);
static void QMHookSaveKey(id self, SEL _cmd, id key, id udid) {
    // Swallow the write: an unvalidated key must never be what gets persisted,
    // and defaults content is irrelevant now that every read is answered here.
}

static void (*origSaveUDID)(id, SEL, id, id, id);
static void QMHookSaveUDID(id self, SEL _cmd, id udid, id name, id product) {
}

static void (*origClearKey)(id, SEL);
static void QMHookClearKey(id self, SEL _cmd) {}

static void (*origClearUDID)(id, SEL);
static void QMHookClearUDID(id self, SEL _cmd) {}

#pragma mark - SKNetwork — never dispatch the pinned request

static void (*origSignedCheck)(id, SEL, id, id, id);
static void QMHookSignedCheck(id self, SEL _cmd, id payload, id query, id completion) {
    LOG(@"HOOK signedCheck intercepted (payload, query, completion=%s)",
        completion ? "set" : "nil");
    if (!completion) {
        LOG(@"HOOK signedCheck: no completion, returning");
        return;
    }
    void (^cb)(id, NSError *) = (void (^)(id, NSError *))completion;
    NSDictionary *envelope = @{
        @"ok": @YES,
        @"valid": @YES,
        @"key": kSyntheticKey,
        @"udid": kSyntheticUDID,
        @"product": kSyntheticProduct,
        @"token": kSyntheticToken,
        @"expires_at": @"2100-01-01 00:00:00",
        @"ip": @"127.0.0.1",
        @"package": @{},
    };
    dispatch_async(dispatch_get_main_queue(), ^{ cb(envelope, nil); });
}

#pragma mark - SKUDIDFlow — no mobileconfig, no callback, no polling

static id (*origFlowShared)(id, SEL);
static id QMHookFlowShared(id self, SEL _cmd) {
    return origFlowShared ? origFlowShared(self, _cmd) : nil;
}

// Swizzles -[UIApplication openURL:] to catch the udid-callback return trip.
// With the callback never happening, the swizzle only adds attack surface.
static void (*origInstallOpenURLHook)(id, SEL);
static void QMHookInstallOpenURLHook(id self, SEL _cmd) {
    LOG(@"HOOK installOpenURLHook blocked");
}

// The return trip itself. Answer NO so nothing else treats it as handled.
static BOOL (*origFlowHandleOpenURL)(id, SEL, id);
static BOOL QMHookFlowHandleOpenURL(id self, SEL _cmd, id url) {
    LOG(@"HOOK handleOpenURL:<%@> ignored", [[url description] substringToIndex:
        MIN((NSUInteger)120, [[url description] length])]);
    return NO;
}

static void (*origStartCapture)(id, SEL, id);
static void QMHookStartCapture(id self, SEL _cmd, id ready) {
    LOG(@"HOOK startCaptureWithReady: blocked (ready=%s)", ready ? "set" : "nil");
    if (!ready) return;
    void (^block)(void) = (void (^)(void))ready;
    dispatch_async(dispatch_get_main_queue(), block);
}

static void (*origStartPolling)(id, SEL);
static void QMHookStartPolling(id self, SEL _cmd) { LOG(@"HOOK startPolling blocked"); }

static void (*origStopPolling)(id, SEL);
static void QMHookStopPolling(id self, SEL _cmd) { LOG(@"HOOK stopPolling"); }

static void (*origPollOnce)(id, SEL);
static void QMHookPollOnce(id self, SEL _cmd) { LOG(@"HOOK pollOnce blocked"); }

static void (*origAppActive)(id, SEL);
static void QMHookAppActive(id self, SEL _cmd) { LOG(@"HOOK appDidBecomeActive ignored"); }

static BOOL (*origHasUDID)(id, SEL);
static BOOL QMHookHasUDID(id self, SEL _cmd) { return YES; }

static id (*origCurrentUDID)(id, SEL);
static id QMHookCurrentUDID(id self, SEL _cmd) { return kSyntheticUDID; }

static void (*origFinishUDID)(id, SEL, id, id, id);
static void QMHookFinishUDID(id self, SEL _cmd, id udid, id name, id product) {
    LOG(@"finishWithUDID suppressed");
}

#pragma mark - SKClient — the state machine

static id (*origClientSavedKey)(id, SEL);
static id QMHookClientSavedKey(id self, SEL _cmd) { return kSyntheticKey; }

static id (*origClientUDID)(id, SEL);
static id QMHookClientUDID(id self, SEL _cmd) { return kSyntheticUDID; }

static id (*origClientToken)(id, SEL);
static id QMHookClientToken(id self, SEL _cmd) { return kSyntheticToken; }

static id (*origClientResolvedToken)(id, SEL);
static id QMHookClientResolvedToken(id self, SEL _cmd) { return kSyntheticToken; }

static id (*origClientExpiredAt)(id, SEL);
static id QMHookClientExpiredAt(id self, SEL _cmd) { return @"2100-01-01 00:00:00"; }

static id (*origClientExpiredAtLocal)(id, SEL);
static id QMHookClientExpiredAtLocal(id self, SEL _cmd) { return @"2100-01-01 00:00:00"; }

static id (*origClientExpiryDate)(id, SEL);
static id QMHookClientExpiryDate(id self, SEL _cmd) {
    return [NSDate dateWithTimeIntervalSince1970:4102444800.0];
}

static BOOL (*origClientHasSession)(id, SEL);
static BOOL QMHookClientHasSession(id self, SEL _cmd) { return YES; }

static BOOL (*origClientAuthWall)(id, SEL);
static BOOL QMHookClientAuthWall(id self, SEL _cmd) { return NO; }

static void (*origValidate)(id, SEL, id, BOOL);
static void QMHookValidate(id self, SEL _cmd, id key, BOOL showUI) {
    LOG(@"HOOK validateWithKey: key=%@ showUI=%d", key ? key : @"(nil)", (int)showUI);
    QMSendO(self, @selector(setLastSubmittedKey:), key ?: kSyntheticKey);
    QMGrantAsync(self, showUI);
}

static void (*origEnsureThenValidate)(id, SEL);
static void QMHookEnsureThenValidate(id self, SEL _cmd) {
    LOG(@"HOOK ensureThenValidate");
    QMGrantAsync(self, NO);
}

static void (*origContinueAfterUDID)(id, SEL);
static void QMHookContinueAfterUDID(id self, SEL _cmd) {
    LOG(@"HOOK continueAfterUDID");
    QMGrantAsync(self, YES);
}

static void (*origStart)(id, SEL);
static void QMHookStart(id self, SEL _cmd) {
    // -start reads udidValue/boundKey and calls -validateWithKey:showUI: when a
    // key exists, otherwise opens the UDID guide. Our validateWithKey grants, so
    // keep the original to let it drive its own flow; the extra grant covers the
    // no-key branch where the original would have opened the capture UI.
    LOG(@"HOOK start -> calling original");
    if (origStart) origStart(self, _cmd);
    LOG(@"HOOK start -> original returned");
    QMGrantAsync(self, NO);
}

static void (*origEnforceLock)(id, SEL);
static void QMHookEnforceLock(id self, SEL _cmd) {
    // Re-runs the lock decision; with fail/ isFatalCode neutralised it is a
    // no-op, so skipping the call avoids a redundant UI teardown.
    LOG(@"HOOK enforceLock blocked");
}

static void (*origFail)(id, SEL, id, id, BOOL);
static void QMHookFail(id self, SEL _cmd, id a, id code, BOOL silent) {
    // Single error funnel for every blade/device/key code. Swallow it so no
    // fatal path, no relock, no bilingual notice can fire.
    QMDiagDumpFail(code, a, silent);
    QMSendB(self, @selector(setValidating:), NO);
    QMSendB(self, @selector(setSilentRevalidating:), NO);
}

static void (*origRevalidateTick)(id, SEL);
static void QMHookRevalidateTick(id self, SEL _cmd) {
    LOG(@"HOOK revalidateTick blocked (remote revocation channel)");
}

static void (*origScheduleRevalidate)(id, SEL);
static void QMHookScheduleRevalidate(id self, SEL _cmd) {
    LOG(@"HOOK scheduleRevalidate blocked");
}

static void (*origKeyFailure)(id, SEL, id, id);
static void QMHookKeyFailure(id self, SEL _cmd, id code, id msg) {
    LOG(@"HOOK handleKeyFailure code=%@ msg=%@", code, msg);
}

static void (*origPromptNewKey)(id, SEL, id);
static void QMHookPromptNewKey(id self, SEL _cmd, id msg) {
    LOG(@"HOOK promptForNewKey blocked msg=%@", msg);
}

static void (*origSubmitKey)(id, SEL, id);
static void QMHookSubmitKey(id self, SEL _cmd, id key) {
    LOG(@"HOOK submitKey: key=%@ -> grant", key);
    QMGrantAsync(self, NO);
}

// Tamper check: the jar carries a 900KB env scanner (frida, substrate, ellekit,
// TrollStore, debugserver, /var/jb ...). It reports through the same funnel, so
// neutralising the entry point is enough.
static BOOL (*origFatalCode)(id, SEL, id);
static BOOL QMHookFatalCode(id self, SEL _cmd, id code) {
    LOG(@"HOOK isFatalCode(%@) -> NO", code);
    return NO;
}

static BOOL (*origKeyErrorCode)(id, SEL, id);
static BOOL QMHookKeyErrorCode(id self, SEL _cmd, id code) {
    LOG(@"HOOK isKeyErrorCode(%@) -> NO", code);
    return NO;
}

#pragma mark - SKHUD — no gates on screen

static void (*origShowUDIDPrompt)(id, SEL, id, id);
static void QMHookShowUDIDPrompt(id self, SEL _cmd, id get, id guide) {
    LOG(@"HOOK showUDIDPrompt blocked");
}

static void (*origShowKeyPrompt)(id, SEL, id, id);
static void QMHookShowKeyPrompt(id self, SEL _cmd, id desc, id cb) {
    LOG(@"HOOK showKeyPrompt blocked desc=%@", desc);
}

static void (*origShowFatal)(id, SEL, id, id);
static void QMHookShowFatal(id self, SEL _cmd, id title, id msg) {
    LOG(@"HOOK showFatalNotice blocked title=%@ msg=%@", title, msg);
}

static void (*origShowNotice)(id, SEL, id, id);
static void QMHookShowNotice(id self, SEL _cmd, id title, id msg) {
    LOG(@"HOOK showNotice blocked title=%@ msg=%@", title, msg);
}

static void (*origShowBlocking)(id, SEL, id, id, id, id);
static void QMHookShowBlocking(id self, SEL _cmd, id title, id msg, id action, id cb) {
    LOG(@"HOOK showBlockingWait blocked title=%@", title);
}

#pragma mark - Remote diagnostics trigger

// A failing bypass is usually a black screen: no way to attach, no way to read
// the log from the device. This puts the dump behind a custom URL scheme so it
// can be triggered from Safari or a second device:
//
//   qosdiag://dump     -> environment + client state + tail of the log
//   qosdiag://reset    -> clear the log file and rewrite headers
//
// Handled by swizzling -[UIApplication openURL:options:completionHandler:] only
// while the app is running; every other URL passes straight through untouched.
static BOOL (*origOpenURL)(id, SEL, id, id, id);
static void QMHookOpenURL(id self, SEL _cmd, id url, id options, id completion) {
    NSString *s = [url absoluteString] ?: @"";
    if (![s hasPrefix:@"qosdiag://"]) {
        if (origOpenURL) origOpenURL(self, _cmd, url, options, completion);
        return;
    }

    NSString *cmd = [s substringFromIndex:@"qosdiag://".length];
    LOG(@"DIAG trigger: %@", cmd);

    Class cls = NSClassFromString(@"SKClient");
    id client = QMSend0((id)cls, @selector(shared));

    if ([cmd hasPrefix:@"reset"]) {
        NSString *p = QMDiagPath();
        [[NSFileManager defaultManager] removeItemAtPath:p error:nil];
        LOG(@"DIAG log reset");
    } else {
        QMDiagDumpEnvironment();
        QMDiagDumpState(client);
        QMDiagLog(@"DIAG dump complete");
    }

    if (completion) {
        void (^cb)(BOOL) = (void (^)(BOOL))completion;
        cb(YES);
    }
}

static void QMInstallAll(void) {
    if (gInstalled) return;

    Class store = NSClassFromString(@"SKStore");
    Class net = NSClassFromString(@"SKNetwork");
    Class flow = NSClassFromString(@"SKUDIDFlow");
    Class client = NSClassFromString(@"SKClient");
    Class hud = NSClassFromString(@"SKHUD");

    if (!store || !client) return;  // PxExtFFi not mapped yet

    if (store) {
        Class sm = QMMetaOf(store);
        QMInstallCls(sm, "boundKey", (IMP)QMHookStoreBoundKey, (IMP *)&origStoreBoundKey);
        QMInstallCls(sm, "savedUDID", (IMP)QMHookStoreSavedUDID, (IMP *)&origStoreSavedUDID);
        QMInstallCls(sm, "savedDeviceName", (IMP)QMHookStoreSavedDeviceName, (IMP *)&origStoreSavedDeviceName);
        QMInstallCls(sm, "savedProduct", (IMP)QMHookStoreSavedProduct, (IMP *)&origStoreSavedProduct);
        QMInstallCls(sm, "saveKey:forUDID:", (IMP)QMHookSaveKey, (IMP *)&origSaveKey);
        QMInstallCls(sm, "saveUDID:deviceName:product:", (IMP)QMHookSaveUDID, (IMP *)&origSaveUDID);
        QMInstallCls(sm, "clearSavedKey", (IMP)QMHookClearKey, (IMP *)&origClearKey);
        QMInstallCls(sm, "clearUDID", (IMP)QMHookClearUDID, (IMP *)&origClearUDID);
    }

    if (net) {
        QMInstallCls(QMMetaOf(net), "signedCheck:extraQuery:completion:", (IMP)QMHookSignedCheck, (IMP *)&origSignedCheck);
    }

    if (flow) {
        Class fm = QMMetaOf(flow);
        QMInstallCls(fm, "shared", (IMP)QMHookFlowShared, (IMP *)&origFlowShared);
        QMInstallCls(fm, "installOpenURLHook", (IMP)QMHookInstallOpenURLHook, (IMP *)&origInstallOpenURLHook);
        QMInstallIns(flow, "startCaptureWithReady:", (IMP)QMHookStartCapture, (IMP *)&origStartCapture);
        QMInstallIns(flow, "startPolling", (IMP)QMHookStartPolling, (IMP *)&origStartPolling);
        QMInstallIns(flow, "stopPolling", (IMP)QMHookStopPolling, (IMP *)&origStopPolling);
        QMInstallIns(flow, "pollOnce", (IMP)QMHookPollOnce, (IMP *)&origPollOnce);
        QMInstallIns(flow, "appDidBecomeActive", (IMP)QMHookAppActive, (IMP *)&origAppActive);
        QMInstallIns(flow, "hasUDID", (IMP)QMHookHasUDID, (IMP *)&origHasUDID);
        QMInstallIns(flow, "currentUDID", (IMP)QMHookCurrentUDID, (IMP *)&origCurrentUDID);
        QMInstallIns(flow, "finishWithUDID:name:product:", (IMP)QMHookFinishUDID, (IMP *)&origFinishUDID);
        QMInstallIns(flow, "handleOpenURL:", (IMP)QMHookFlowHandleOpenURL, (IMP *)&origFlowHandleOpenURL);
    }

    if (client) {
        QMInstallIns(client, "savedKey", (IMP)QMHookClientSavedKey, (IMP *)&origClientSavedKey);
        QMInstallIns(client, "udidValue", (IMP)QMHookClientUDID, (IMP *)&origClientUDID);
        QMInstallIns(client, "token", (IMP)QMHookClientToken, (IMP *)&origClientToken);
        QMInstallIns(client, "resolvedToken", (IMP)QMHookClientResolvedToken, (IMP *)&origClientResolvedToken);
        QMInstallIns(client, "expiredAtString", (IMP)QMHookClientExpiredAt, (IMP *)&origClientExpiredAt);
        QMInstallIns(client, "expiredAtLocalString", (IMP)QMHookClientExpiredAtLocal, (IMP *)&origClientExpiredAtLocal);
        QMInstallIns(client, "expiryDate", (IMP)QMHookClientExpiryDate, (IMP *)&origClientExpiryDate);
        QMInstallIns(client, "hasValidatedSession", (IMP)QMHookClientHasSession, (IMP *)&origClientHasSession);
        QMInstallIns(client, "authWallRequired", (IMP)QMHookClientAuthWall, (IMP *)&origClientAuthWall);
        QMInstallIns(client, "validateWithKey:showUI:", (IMP)QMHookValidate, (IMP *)&origValidate);
        QMInstallIns(client, "ensureThenValidate", (IMP)QMHookEnsureThenValidate, (IMP *)&origEnsureThenValidate);
        QMInstallIns(client, "continueAfterUDID", (IMP)QMHookContinueAfterUDID, (IMP *)&origContinueAfterUDID);
        QMInstallIns(client, "start", (IMP)QMHookStart, (IMP *)&origStart);
        QMInstallIns(client, "fail:code:silent:", (IMP)QMHookFail, (IMP *)&origFail);
        QMInstallIns(client, "revalidateTick", (IMP)QMHookRevalidateTick, (IMP *)&origRevalidateTick);
        QMInstallIns(client, "scheduleRevalidate", (IMP)QMHookScheduleRevalidate, (IMP *)&origScheduleRevalidate);
        QMInstallIns(client, "handleKeyFailureWithCode:message:", (IMP)QMHookKeyFailure, (IMP *)&origKeyFailure);
        QMInstallIns(client, "promptForNewKeyWithMessage:", (IMP)QMHookPromptNewKey, (IMP *)&origPromptNewKey);
        QMInstallIns(client, "submitKey:", (IMP)QMHookSubmitKey, (IMP *)&origSubmitKey);
        QMInstallIns(client, "isFatalCode:", (IMP)QMHookFatalCode, (IMP *)&origFatalCode);
        QMInstallIns(client, "isKeyErrorCode:", (IMP)QMHookKeyErrorCode, (IMP *)&origKeyErrorCode);
        QMInstallIns(client, "enforceLock", (IMP)QMHookEnforceLock, (IMP *)&origEnforceLock);
    }

    if (hud) {
        QMInstallIns(hud, "showUDIDPrompt:guide:", (IMP)QMHookShowUDIDPrompt, (IMP *)&origShowUDIDPrompt);        QMInstallIns(hud, "showKeyPrompt:onSubmit:", (IMP)QMHookShowKeyPrompt, (IMP *)&origShowKeyPrompt);
        QMInstallIns(hud, "showFatalNotice:message:", (IMP)QMHookShowFatal, (IMP *)&origShowFatal);
        QMInstallIns(hud, "showNotice:message:", (IMP)QMHookShowNotice, (IMP *)&origShowNotice);
        QMInstallIns(hud, "showBlockingWait:message:actionTitle:onAction:", (IMP)QMHookShowBlocking, (IMP *)&origShowBlocking);
    }

    LOG(@"INSTALL summary store=%d net=%d flow=%d client=%d hud=%d",
        store != nil, net != nil, flow != nil, client != nil, hud != nil);

    // Diagnostic URL handler, read-only side effect on the log file.
    Class app = NSClassFromString(@"UIApplication");
    if (app) {
        QMInstallIns(app, "openURL:options:completionHandler:",
                     (IMP)QMHookOpenURL, (IMP *)&origOpenURL);
    }

    QMDiagDumpEnvironment();
    gInstalled = YES;

    Class c = NSClassFromString(@"SKClient");
    id shared = QMSend0((id)c, @selector(shared));
    if (shared) QMGrant(shared, NO);
}

#pragma mark - Late-bind driver

// PxExtFFi is a dependent framework, so it is usually mapped before this dylib
// runs its constructor. Never assume it: poll until SKStore/SKClient exist, then
// install once. 60 attempts x 250ms = 15s ceiling, no unbounded loop.
static void QMScheduleInstall(void) {
    static int attempts = 0;
    if (gInstalled) return;

    Class probe = NSClassFromString(@"SKClient");
    if (!probe) {
        // Only log every 10th attempt: at 250ms a full 15s poll would otherwise
        // bury the interesting lines under 60 copies of the same message.
        if (attempts % 10 == 0) {
            LOG(@"WAIT attempt %d: SKClient not mapped yet", attempts);
        }
    }

    QMInstallAll();
    if (gInstalled) return;

    if (++attempts > 60) {
        LOG(@"GIVE UP after %d attempts: PxExtFFi never appeared", attempts);
        QMDiagDumpEnvironment();
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{ QMScheduleInstall(); });
}

#pragma mark - Entry

__attribute__((constructor)) static void QMInit(void) {
    @autoreleasepool {
        QMDiagOpen();
        LOG(@"==== QoSMetrics loaded pid=%d ====", getpid());
        LOG(@"log file: %@", QMDiagPath());
        dispatch_async(dispatch_get_main_queue(), ^{ QMScheduleInstall(); });
    }
}
