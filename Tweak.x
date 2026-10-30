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
#import <QuartzCore/QuartzCore.h>
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
// BOOL getter: QMSend0 would misinterpret the return register.
static BOOL QMSendB0(id t, SEL s) {
    if (!t || ![t respondsToSelector:s]) return NO;
    return ((BOOL (*)(id, SEL))[t methodForSelector:s])(t, s);
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

// Licensing state only — no UI, no dispatch. Every flag the framework's own
// guards read is set here, so a later call into the original code takes the
// already-validated branch instead of bailing out. Safe to call on any thread
// the framework itself would use: it only sends setters.
static void QMApplyState(id client) {
    if (!client) return;

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
}

static UIWindow *QMKeyWindow(void) {
    UIWindow *w = nil;
    for (UIScene *s in [[UIApplication sharedApplication] connectedScenes]) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *cand in ((UIWindowScene *)s).windows) {
            if (cand.isKeyWindow) return cand;
        }
    }
    // Pre-iOS-13 fallback and the case where the key window is still nil during
    // launch: the first window in the scene stack is good enough to parent to.
    if (!w) {
        for (UIScene *s in [[UIApplication sharedApplication] connectedScenes]) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *cand in ((UIWindowScene *)s).windows) { w = cand; break; }
            if (w) break;
        }
    }
    if (!w) w = [UIApplication sharedApplication].keyWindow;
    return w;
}

static void QMShowMenu(void);

// Guaranteed way into the menu that does not depend on any framework widget:
// a two-finger tap on the key window. cancelsTouchesInView is left off so the
// game still receives every touch as usual.
@interface QMTapTarget : NSObject
- (void)qmHandleTap:(UITapGestureRecognizer *)g;
@end

@implementation QMTapTarget
- (void)qmHandleTap:(UITapGestureRecognizer *)g {
    QMDiagLog(@"GESTURE two-finger tap -> toggle menu");
    QMShowMenu();
}
@end

static QMTapTarget *gTapTarget = nil;

static void QMInstallMenuGesture(UIWindow *win) {
    if (!win || gTapTarget) return;
    gTapTarget = [[QMTapTarget alloc] init];
    UITapGestureRecognizer *g =
        [[UITapGestureRecognizer alloc] initWithTarget:gTapTarget
                                                action:@selector(qmHandleTap:)];
    g.numberOfTouchesRequired = 2;
    g.numberOfTapsRequired = 1;
    g.cancelsTouchesInView = NO;
    [win addGestureRecognizer:g];
    QMDiagLog(@"UI: two-finger tap installed on window %p", (__bridge void *)win);
}

// Last resort, and the one that actually cannot fail: a plain UIButton on the
// key window. No framework class, no image asset, no -setupUI. When every widget
// the framework owns stays invisible, this is still on screen and still taps.
@interface QMMenuButtonTarget : NSObject
- (void)qmMenuButtonTapped:(UIButton *)b;
@end

@implementation QMMenuButtonTarget
- (void)qmMenuButtonTapped:(UIButton *)b {
    QMDiagLog(@"BUTTON tap -> toggle menu");
    QMShowMenu();
}
@end

static QMMenuButtonTarget *gMenuButtonTarget = nil;
static UIButton *gMenuButton = nil;

static void QMInstallMenuButton(UIWindow *win) {
    if (!win) return;
    if (!gMenuButtonTarget) gMenuButtonTarget = [[QMMenuButtonTarget alloc] init];

    if (!gMenuButton) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16.0, 96.0, 64.0, 64.0);
        b.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.55];
        b.layer.cornerRadius = 32.0;
        b.layer.borderWidth = 1.5;
        b.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.85].CGColor;
        b.clipsToBounds = YES;
        [b setTitle:@"MENU" forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12.0];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [b addTarget:gMenuButtonTarget
              action:@selector(qmMenuButtonTapped:)
    forControlEvents:UIControlEventTouchUpInside];
        gMenuButton = b;
        QMDiagLog(@"UI: plain menu button created");
    }
    if (gMenuButton.superview != win) {
        [win addSubview:gMenuButton];
        QMDiagLog(@"UI: plain menu button attached to %p", (__bridge void *)win);
    }
    gMenuButton.hidden = NO;
    gMenuButton.alpha = 1.0;
    gMenuButton.userInteractionEnabled = YES;
    [win bringSubviewToFront:gMenuButton];
}

static void QMLogView(NSString *label, id view) {
    if (!view || ![view isKindOfClass:[UIView class]]) {
        QMDiagLog(@"%@ = %p (not a view)", label, (__bridge void *)view);
        return;
    }
    UIView *v = (UIView *)view;
    QMDiagLog(@"%@ = %s %p frame=%@ hidden=%d alpha=%.2f superview=%p window=%p",
              label, class_getName([v class]), (__bridge void *)v,
              NSStringFromCGRect(v.frame), (int)v.hidden, (double)v.alpha,
              (__bridge void *)v.superview, (__bridge void *)v.window);
}

// A view built before the key window existed has no window of its own — it
// exists, is sized, and is completely invisible. Parent it again.
static void QMAttachToWindow(id view, UIWindow *win, BOOL hideUnlessShown) {
    if (!win || !view || ![view isKindOfClass:[UIView class]]) return;
    UIView *v = (UIView *)view;
    if (v.window) return;
    BOOL wasHidden = v.hidden;
    [win addSubview:v];
    if (hideUnlessShown) v.hidden = YES; else v.hidden = wasHidden;
    QMDiagLog(@"UI: attached %s to key window", class_getName([v class]));
}

// -[UIManager setupUI] is 146 KB of obfuscated code and returns early: on device
// only the TPP camera button came up, and that button is built lazily by
// -showTPPButton:, which we call ourselves — so setupUI never reached its
// +0x4478 (+[FloatingButton buttonWithFrame:]) / +0x449c (-setFloatingButton:)
// block at all. Both widgets we want are self-initialising constructors, so
// build them directly when setupUI leaves them nil:
//   +[MenuView menuWithFrame:]         -> -initWithFrame: , -setupUI
//   +[FloatingButton buttonWithFrame:] -> +buttonWithType: , -setFrame: , -setup
static id QMMenuViewNew(CGRect frame) {
    Class mv = NSClassFromString(@"MenuView");
    if (!mv || ![mv respondsToSelector:@selector(menuWithFrame:)]) return nil;
    id (*fn)(id, SEL, CGRect) =
        (id (*)(id, SEL, CGRect))[(id)mv methodForSelector:@selector(menuWithFrame:)];
    return fn((id)mv, @selector(menuWithFrame:), frame);
}

static id QMFloatButtonNew(CGRect frame) {
    Class fb = NSClassFromString(@"FloatingButton");
    if (!fb || ![fb respondsToSelector:@selector(buttonWithFrame:)]) return nil;
    id (*fn)(id, SEL, CGRect) =
        (id (*)(id, SEL, CGRect))[(id)fb methodForSelector:@selector(buttonWithFrame:)];
    return fn((id)fb, @selector(buttonWithFrame:), frame);
}

static void QMEnsureUI(void) {
    Class mgr = NSClassFromString(@"UIManager");
    if (!mgr) { QMDiagLog(@"UI: UIManager absent"); return; }

    id shared = QMSend0((id)mgr, @selector(shared));
    if (!shared) { QMDiagLog(@"UI: UIManager.shared nil"); return; }

    if (![NSThread isMainThread]) {
        QMDiagLog(@"UI: not on main thread -> hopping");
        dispatch_async(dispatch_get_main_queue(), ^{ QMEnsureUI(); });
        return;
    }

    id menu = QMSend0(shared, @selector(menu));
    id tpp = QMSend0(shared, @selector(tppButton));
    QMDiagLog(@"UI: pass menu=%p tpp=%p", (__bridge void *)menu, (__bridge void *)tpp);

    // setupUI builds the whole tree from scratch; a second call stacks a second
    // copy and orphans the first. Only ever force it once per process.
    static BOOL forcedSetupUI = NO;
    if (!menu && !tpp && !forcedSetupUI) {
        forcedSetupUI = YES;
        QMDiagLog(@"UI: tree missing -> setupUI");
        QMSendV(shared, @selector(setupUI));
        menu = QMSend0(shared, @selector(menu));
        tpp = QMSend0(shared, @selector(tppButton));
        QMDiagLog(@"UI: after setupUI menu=%p tpp=%p", (__bridge void *)menu, (__bridge void *)tpp);
    }

    UIWindow *win = QMKeyWindow();
    QMDiagLog(@"UI: keyWindow=%p bounds=%@", (__bridge void *)win,
              win ? NSStringFromCGRect(win.bounds) : @"(none)");
    QMInstallMenuGesture(win);
    QMInstallMenuButton(win);

    // setupUI bailed before creating the menu -> build one. MenuView fills
    // itself in -setupUI, including its own tab bar, so this is not a shell.
    if (!menu && win) {
        menu = QMMenuViewNew(win.bounds);
        QMDiagLog(@"UI: built MenuView %p", (__bridge void *)menu);
        if (menu) QMSendO(shared, @selector(setMenu:), menu);
    }

    // The button is created lazily here, and this is what un-hides an existing one.
    QMSendB(shared, @selector(showTPPButton:), YES);
    if ([shared respondsToSelector:@selector(updateTPPButtonState:)])
        QMSendB(shared, @selector(updateTPPButtonState:), YES);

    menu = QMSend0(shared, @selector(menu));
    tpp = QMSend0(shared, @selector(tppButton));
    id esp = QMSend0(shared, @selector(espOverlay));

    QMLogView(@"UI: menu", menu);
    QMLogView(@"UI: tpp", tpp);
    QMLogView(@"UI: esp", esp);

    // The TPP switch is a floating view too; it must be on screen to be tapped.
    if ([tpp isKindOfClass:[UIView class]]) {
        UIView *v = (UIView *)tpp;
        QMAttachToWindow(v, win, NO);
        if (v.hidden) { v.hidden = NO; QMDiagLog(@"UI: tpp un-hidden"); }
        if (v.alpha < 0.99) { v.alpha = 1.0; QMDiagLog(@"UI: tpp alpha restored"); }
        v.userInteractionEnabled = YES;
        if (CGRectIsEmpty(v.frame) && win)
            v.frame = CGRectMake(win.bounds.size.width - 72.0, 96.0, 56.0, 56.0);
    }

    // The menu view only needs a parent to be toggled into; keep it hidden so
    // it never covers the game until the button is tapped.
    if ([menu isKindOfClass:[UIView class]]) QMAttachToWindow(menu, win, YES);
    if ([esp isKindOfClass:[UIView class]]) QMAttachToWindow(esp, win, YES);

    // The mod-menu handle is FloatingButton, a different class from the TPP
    // camera switch the player already sees. setupUI builds it at +0x4478
    // (+buttonWithFrame:), stores it at +0x449c (-setFloatingButton:) and wires
    // its tap to -toggleMenu (+0x9040 -setOnTap:, +0x203ec -toggleMenu) — but it
    // never got there. Build it ourselves; -buttonWithFrame: already calls -setup.
    id floatBtn = QMSend0(shared, @selector(floatingButton));
    QMLogView(@"UI: floatingButton", floatBtn);
    if (!floatBtn && win) {
        floatBtn = QMFloatButtonNew(CGRectMake(16.0, 96.0, 56.0, 56.0));
        QMDiagLog(@"UI: built FloatingButton %p", (__bridge void *)floatBtn);
        if (floatBtn) QMSendO(shared, @selector(setFloatingButton:), floatBtn);
    }
    if ([floatBtn isKindOfClass:[UIView class]]) {
        UIView *v = (UIView *)floatBtn;
        QMAttachToWindow(v, win, NO);
        if (v.hidden) { v.hidden = NO; QMDiagLog(@"UI: floatingButton un-hidden"); }
        if (v.alpha < 0.99) { v.alpha = 1.0; QMDiagLog(@"UI: floatingButton alpha restored"); }
        v.userInteractionEnabled = YES;
        if (CGRectIsEmpty(v.frame) && win)
            v.frame = CGRectMake(16.0, 96.0, 56.0, 56.0);
        if ([floatBtn respondsToSelector:@selector(makeDraggable)])
            QMSendV(floatBtn, @selector(makeDraggable));

        // setupUI normally wires this; a nil onTap means the button is dead.
        if ([floatBtn respondsToSelector:@selector(onTap)] &&
            !QMSend0(floatBtn, @selector(onTap))) {
            QMDiagLog(@"UI: floatingButton onTap was nil -> wiring toggleMenu");
            void (^tap)(void) = ^{ QMSendV(shared, @selector(toggleMenu)); };
            QMSendO(floatBtn, @selector(setOnTap:), tap);
        }
    }

    QMDiagLog(@"UI: pass done menu=%p tpp=%p float=%p",
              (__bridge void *)QMSend0(shared, @selector(menu)),
              (__bridge void *)QMSend0(shared, @selector(tppButton)),
              (__bridge void *)QMSend0(shared, @selector(floatingButton)));
}

// -[UIManager toggleMenu] is the one thing that puts MenuView on screen: it
// does the addSubview:/removeFromSuperview itself (verified at +0x2a78 and
// +0x959c), and it is what -[FloatingButton buttonTapped] reaches through its
// onTap block. Callable directly, so the menu can be opened without the button.
static void QMShowMenu(void) {
    Class mgr = NSClassFromString(@"UIManager");
    if (!mgr) { QMDiagLog(@"MENU: UIManager absent"); return; }
    id shared = QMSend0((id)mgr, @selector(shared));
    if (!shared) { QMDiagLog(@"MENU: shared nil"); return; }
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ QMShowMenu(); });
        return;
    }

    if (!QMSend0(shared, @selector(menu))) {
        QMDiagLog(@"MENU: no MenuView yet -> building one");
        UIWindow *w = QMKeyWindow();
        if (w) {
            id m = QMMenuViewNew(w.bounds);
            if (m) QMSendO(shared, @selector(setMenu:), m);
        }
    }
    id menu = QMSend0(shared, @selector(menu));
    if ([menu isKindOfClass:[UIView class]]) {
        UIWindow *win = QMKeyWindow();
        if (win && !((UIView *)menu).window) {
            [win addSubview:(UIView *)menu];
            QMDiagLog(@"MENU: MenuView had no window -> attached");
        }
    }

    UIView *mv = [menu isKindOfClass:[UIView class]] ? (UIView *)menu : nil;
    BOOL wasVisible = mv && mv.window && !mv.hidden && mv.alpha > 0.01;

    QMDiagLog(@"MENU: toggleMenu (wasVisible=%d)", (int)wasVisible);
    QMSendV(shared, @selector(toggleMenu));

    if (mv) {
        BOOL nowVisible = mv.window && !mv.hidden && mv.alpha > 0.01;
        // toggleMenu is the framework's own open/close switch, but it is also a
        // 146 KB obfuscated neighbour of setupUI with its own guards. If it
        // opened nothing while the menu was closed, put the view up ourselves.
        if (!wasVisible && !nowVisible) {
            QMDiagLog(@"MENU: toggleMenu no-op -> forcing MenuView visible");
            UIWindow *win = QMKeyWindow();
            if (!mv.window && win) [win addSubview:mv];
            if (CGRectIsEmpty(mv.frame) && win) mv.frame = win.bounds;
            mv.hidden = NO;
            mv.alpha = 1.0;
            mv.userInteractionEnabled = YES;
            if (win) [win bringSubviewToFront:mv];
        }
    }
    QMLogView(@"MENU: menu after toggle", QMSend0(shared, @selector(menu)));
}

// The grant can land before the key window exists (launch, orientation change,
// overlay teardown). Run a handful of passes instead of guessing one moment.
static void QMEnsureUILater(void) {
    static const double kDelays[] = {0.5, 1.5, 3.0, 6.0, 10.0};
    for (size_t i = 0; i < sizeof(kDelays) / sizeof(kDelays[0]); i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                    (int64_t)(kDelays[i] * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ QMEnsureUI(); });
    }
}

// The three blocks the host app registers through the C API
// (apiclient_on_check_package / on_check_device / on_login). This is the exact
// tail of -[SKClient handleResponse:error:], verified in the disassembly:
//
//   if (onCheckPackage) onCheckPackage(sessionToken);
//   if (onCheckDevice)  onCheckDevice(devicePayload, sessionToken);
//   if (onLoginSuccess) onLoginSuccess();
//
// Missing any of them leaves the app's own post-login code — the part that
// builds and enables its menu — never called, which is why a bypass that only
// fired onLoginSuccess still showed no menu.
static void QMFireCallbacks(id client) {
    if (!client) return;

    id token = QMSend0(client, @selector(sessionToken)) ?: kSyntheticToken;
    id device = QMSend0(client, @selector(devicePayload)) ?: @{};

    id cbPackage = QMSend0(client, @selector(onCheckPackage));
    LOG(@"CALLBACK onCheckPackage=%s", cbPackage ? "set" : "nil");
    if (cbPackage) ((void (^)(id))cbPackage)(token);

    id cbDevice = QMSend0(client, @selector(onCheckDevice));
    LOG(@"CALLBACK onCheckDevice=%s", cbDevice ? "set" : "nil");
    if (cbDevice) ((void (^)(id, id))cbDevice)(device, token);

    id cbLogin = QMSend0(client, @selector(onLoginSuccess));
    LOG(@"CALLBACK onLoginSuccess=%s", cbLogin ? "set" : "nil");
    if (cbLogin) ((void (^)(void))cbLogin)();
}

static void QMGrant(id client, BOOL showCard) {
    if (!client) {
        LOG(@"GRANT aborted: client is nil");
        return;
    }
    LOG(@"GRANT begin showCard=%d", (int)showCard);
    QMDiagDumpState(client);

    QMApplyState(client);

    // Callback order follows the framework: the host builds its UI from these,
    // pending blocks run afterwards.
    QMFireCallbacks(client);
    QMSendV(client, @selector(runPendingBlocks));

    id hud = QMSend0(client, @selector(hud));
    QMSendV(hud, @selector(hideLoading));
    QMSendV(hud, @selector(hideBlockingWait));

    QMEnsureUILater();

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

    // Nothing may stay on top of the game: a prompt left up keeps SKHUD's
    // blocking shield in the host view, which covers the menu and eats touches.
    QMSendV(hud, @selector(dismissAll));
    QMSendV(hud, @selector(dropShieldIfIdle));
    LOG(@"GRANT overlay cleared (visible=%d)", (int)QMSendB0(hud, @selector(hasVisibleHUD)));

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
    // Apply before returning: anything that runs on the same turn already sees
    // a licensed client instead of the pre-validation default.
    QMApplyState(self);
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
    // -start is the framework's own boot path. It reads hasValidatedSession /
    // hideUI through -uiAllowed and bails out of everything when the client is
    // not licensed, so the state has to be applied BEFORE the original runs —
    // otherwise the original takes the unlicensed branch and the UI it would
    // have built never appears.
    LOG(@"HOOK start -> applying state, then original");
    QMApplyState(self);
    if (origStart) origStart(self, _cmd);
    LOG(@"HOOK start -> original returned");
    QMGrantAsync(self, NO);
}

// -uiAllowed is the single question the framework asks before it shows anything.
static BOOL (*origUIAllowed)(id, SEL);
static BOOL QMHookUIAllowed(id self, SEL _cmd) {
    BOOL real = origUIAllowed ? origUIAllowed(self, _cmd) : NO;
    LOG(@"HOOK uiAllowed -> YES (real=%d)", (int)real);
    return YES;
}

static BOOL (*origHideUI)(id, SEL);
static BOOL QMHookHideUI(id self, SEL _cmd) {
    BOOL real = origHideUI ? origHideUI(self, _cmd) : NO;
    LOG(@"HOOK hideUI -> NO (real=%d)", (int)real);
    return NO;
}

// Teardown removes the menu tree the framework just built. Hooking it is not
// paranoia: the env scanner and the revocation tick both route here, and a
// menu that vanishes seconds after appearing is the visible symptom.
static void (*origTeardownUI)(id, SEL);
static void QMHookTeardownUI(id self, SEL _cmd) {
    LOG(@"HOOK teardownUI blocked");
}

// Observation only, no behaviour change: these answer "who builds the menu, and
// does the framework ever reach it on its own". If nothing is logged for
// +shared / -setupUI except our own forced pass, the tree really is dead code
// in this build and the only way to it is the forced call.
static id (*origUIShared)(id, SEL);
static id QMHookUIShared(id self, SEL _cmd) {
    id r = origUIShared ? origUIShared(self, _cmd) : nil;
    LOG(@"HOOK +[UIManager shared] -> %p (external caller)", (__bridge void *)r);
    return r;
}

static void (*origSetupUI)(id, SEL);
static void QMHookSetupUI(id self, SEL _cmd) {
    LOG(@"HOOK -[UIManager setupUI] enter");
    if (origSetupUI) origSetupUI(self, _cmd);
    QMLogView(@"HOOK setupUI menu", QMSend0(self, @selector(menu)));
    QMLogView(@"HOOK setupUI tpp", QMSend0(self, @selector(tppButton)));
}

static void (*origShowTPP)(id, SEL, BOOL);
static void QMHookShowTPP(id self, SEL _cmd, BOOL on) {
    LOG(@"HOOK -[UIManager showTPPButton:%d]", (int)on);
    if (origShowTPP) origShowTPP(self, _cmd, on);
    QMLogView(@"HOOK showTPP tpp", QMSend0(self, @selector(tppButton)));
}

static void (*origToggleMenu)(id, SEL);
static void QMHookToggleMenu(id self, SEL _cmd) {
    LOG(@"HOOK -[UIManager toggleMenu]");
    if (origToggleMenu) origToggleMenu(self, _cmd);
    QMLogView(@"HOOK toggleMenu menu", QMSend0(self, @selector(menu)));
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
//   qosdiag://menu     -> open (toggle) the mod menu, no button needed
//   qosdiag://ui       -> run one forced UI pass right now
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
    } else if ([cmd hasPrefix:@"menu"]) {
        QMShowMenu();
    } else if ([cmd hasPrefix:@"ui"]) {
        QMEnsureUI();
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
        QMInstallIns(client, "uiAllowed", (IMP)QMHookUIAllowed, (IMP *)&origUIAllowed);
        QMInstallIns(client, "hideUI", (IMP)QMHookHideUI, (IMP *)&origHideUI);
    }

    if (hud) {
        QMInstallIns(hud, "showUDIDPrompt:guide:", (IMP)QMHookShowUDIDPrompt, (IMP *)&origShowUDIDPrompt);
        QMInstallIns(hud, "showKeyPrompt:onSubmit:", (IMP)QMHookShowKeyPrompt, (IMP *)&origShowKeyPrompt);
        QMInstallIns(hud, "showFatalNotice:message:", (IMP)QMHookShowFatal, (IMP *)&origShowFatal);
        QMInstallIns(hud, "showNotice:message:", (IMP)QMHookShowNotice, (IMP *)&origShowNotice);
        QMInstallIns(hud, "showBlockingWait:message:actionTitle:onAction:", (IMP)QMHookShowBlocking, (IMP *)&origShowBlocking);
    }

    LOG(@"INSTALL summary store=%d net=%d flow=%d client=%d hud=%d",
        store != nil, net != nil, flow != nil, client != nil, hud != nil);

    // The menu/overlay tree belongs to the framework's own boot path. Forcing it
    // here would build it before there is a window and orphan it, so only the
    // licensing state is touched at install time.
    Class uiMgr = NSClassFromString(@"UIManager");
    if (uiMgr) {
        QMInstallIns(uiMgr, "teardownUI", (IMP)QMHookTeardownUI, (IMP *)&origTeardownUI);
        QMInstallIns(uiMgr, "setupUI", (IMP)QMHookSetupUI, (IMP *)&origSetupUI);
        QMInstallIns(uiMgr, "showTPPButton:", (IMP)QMHookShowTPP, (IMP *)&origShowTPP);
        QMInstallIns(uiMgr, "toggleMenu", (IMP)QMHookToggleMenu, (IMP *)&origToggleMenu);
        QMInstallCls(uiMgr, "shared", (IMP)QMHookUIShared, (IMP *)&origUIShared);
    }

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
    if (shared) QMApplyState(shared);
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
