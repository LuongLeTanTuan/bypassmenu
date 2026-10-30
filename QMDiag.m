// QMDiag.m — see QMDiag.h.
//
// Design notes:
//   * The file is opened once, on first use, and kept open for the process
//     lifetime. Reopening per line costs a syscall triple and loses ordering.
//   * NSLog is always mirrored: if the file cannot be opened at all (sandbox,
//     read-only path) the console stream is the only surviving channel.
//   * Every hook install is verified by reading the IMP back. A hook that did
//     not land is reported as MISS rather than assumed to work.

#import "QMDiag.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <unistd.h>
#import <sys/time.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <string.h>
#import <errno.h>
#import <fcntl.h>

static int gFD = -1;
static NSString *gPath = nil;
static NSLock *gLock = nil;
static id gInitLock = nil;
static NSMutableArray<NSString *> *gRecent = nil;   // ring buffer for the dump

// Sentinel object so plain C functions have something stable for @synchronized.
@interface QMDiagSentinel : NSObject
+ (instancetype)shared;
@end

@implementation QMDiagSentinel
+ (instancetype)shared {
    static QMDiagSentinel *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [QMDiagSentinel new]; });
    return s;
}
@end

// dlsym rather than direct linkage: the dyld introspection symbols are not part
// of the public SDK on every deployment target the tweak supports, and a direct
// call fails to link on older ones.
static int QMDyldImageCount(void) {
    static int (*fn)(void);
    static dispatch_once_t once;
    dispatch_once(&once, ^{ fn = (int (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count"); });
    return fn ? fn() : 0;
}

static const char *QMDyldImageName(int i) {
    static const char *(*fn)(int);
    static dispatch_once_t once;
    dispatch_once(&once, ^{ fn = (const char *(*)(int))dlsym(RTLD_DEFAULT, "_dyld_get_image_name"); });
    return fn ? fn(i) : NULL;
}

static NSString *QMDiagPickPath(void) {
    NSArray<NSString *> *candidates = @[
        @"/var/mobile/Library/Logs/QoSMetrics.log",
        @"/var/jb/var/mobile/Library/Logs/QoSMetrics.log",
    ];
    for (NSString *p in candidates) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *dir = [p stringByDeletingLastPathComponent];
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        if ([fm isWritableFileAtPath:dir]) {
            [fm createFileAtPath:p contents:nil attributes:nil];
            if ([fm isWritableFileAtPath:p]) return p;
        }
    }
    // Sandboxed fallback: app container Documents.
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (docs.length) return [docs stringByAppendingPathComponent:@"QoSMetrics.log"];
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"QoSMetrics.log"];
}

NSString *QMDiagPath(void) {
    // @synchronized needs an object; a plain function has no reliable self, so
    // a dedicated sentinel guards initialisation instead.
    @synchronized([QMDiagSentinel shared]) {
        if (!gPath) gPath = QMDiagPickPath();
        return gPath;
    }
}

void QMDiagOpen(void) {
    @synchronized([QMDiagSentinel shared]) {
        if (gLock) return;
        gLock = [NSLock new];
        gRecent = [NSMutableArray arrayWithCapacity:64];
        gPath = QMDiagPickPath();
        gFD = open(gPath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (gFD < 0) {
            NSLog(@"[QoSMetrics] log open failed: %@ errno=%d", gPath, errno);
        }
    }
}

static void QMDiagWriteLine(NSString *line) {
    if (!gLock) QMDiagOpen();

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    NSString *stamp = [NSString stringWithFormat:@"%02d:%02d:%02d.%03d",
                       tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000)];
    NSString *out = [NSString stringWithFormat:@"%@ [%d] %@\n", stamp, getpid(), line];

    [gLock lock];
    if (gFD >= 0) {
        NSData *d = [out dataUsingEncoding:NSUTF8StringEncoding];
        ssize_t off = 0;
        const uint8_t *bytes = d.bytes;
        NSUInteger total = d.length;
        while (off < (ssize_t)total) {
            ssize_t n = write(gFD, bytes + off, total - (NSUInteger)off);
            if (n <= 0) break;
            off += n;
        }
    }
    [gRecent addObject:line];
    while (gRecent.count > 200) [gRecent removeObjectAtIndex:0];
    [gLock unlock];

    NSLog(@"[QoSMetrics] %@", line);
}

void QMDiagLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    QMDiagWriteLine(msg);
}

// Container-typed diagnostics never count as "what's inside" — printing a
// dictionary wholesale invites two failure modes: a crash on a bad object, and
// a log so large the useful line is buried. Type + count only.
static NSString *QMDescribe(id obj) {
    if (!obj) return @"nil";
    if (obj == [NSNull null]) return @"NSNull";
    if ([obj isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)obj;
        if (s.length > 120) s = [[s substringToIndex:120] stringByAppendingString:@"…"];
        return [NSString stringWithFormat:@"NSString(\"%@\") len=%lu", s, (unsigned long)[(NSString *)obj length]];
    }
    if ([obj isKindOfClass:[NSNumber class]]) {
        return [NSString stringWithFormat:@"NSNumber(%@)", obj];
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        // Key names only when small: they identify payload shape without dumping
        // user data, and they are what tells you packagePayload is empty vs wrong.
        if (d.count && d.count <= 12) {
            NSArray *keys = [[d allKeys] sortedArrayUsingSelector:@selector(compare:)];
            NSMutableArray *names = [NSMutableArray array];
            for (id k in keys) {
                if ([k isKindOfClass:[NSString class]]) [names addObject:k];
            }
            return [NSString stringWithFormat:@"NSDictionary(%lu) keys=[%@]",
                    (unsigned long)d.count, [names componentsJoinedByString:@","]];
        }
        return [NSString stringWithFormat:@"NSDictionary(%lu)", (unsigned long)d.count];
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        return [NSString stringWithFormat:@"NSArray(%lu)", (unsigned long)[(NSArray *)obj count]];
    }
    if ([obj isKindOfClass:[NSDate class]]) {
        return [NSString stringWithFormat:@"NSDate(%@)", obj];
    }
    return [NSString stringWithFormat:@"%s", object_getClassName(obj)];
}

BOOL QMDiagVerifyHook(Class cls, SEL sel, IMP expected, const char *label) {
    if (!cls || !sel) {
        QMDiagLog(@"VERIFY %-42s MISSING class/sel", label);
        return NO;
    }
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        QMDiagLog(@"VERIFY %-42s MISSING selector", label);
        return NO;
    }
    IMP got = method_getImplementation(m);
    // On arm64e the IMP is signed; comparing the raw pointer can differ from
    // what was installed even when the forward pointer is ours. Compare the
    // decoded pointers via imp_implementationWithBlock is not applicable here,
    // so compare ptrauth-stripped values.
    uintptr_t a = (uintptr_t)got & 0x00007FFFFFFFFFFF;
    uintptr_t b = (uintptr_t)expected & 0x00007FFFFFFFFFFF;
    BOOL ok = (a == b);
    QMDiagLog(@"VERIFY %-42s %s (imp=%p want=%p)",
              label, ok ? "OK" : "MISMATCH", (void *)got, (void *)expected);
    return ok;
}

void QMDiagDumpEnvironment(void) {
    QMDiagLog(@"---- environment ----");
    QMDiagLog(@"log path      : %@", QMDiagPath());
    QMDiagLog(@"pid           : %d", getpid());
    QMDiagLog(@"bundle        : %@", [[NSBundle mainBundle] bundleIdentifier]);
    QMDiagLog(@"os            : %@", [[NSProcessInfo processInfo] operatingSystemVersionString]);
    QMDiagLog(@"jb paths      : /var/jb=%d /usr/lib/substrate=%d",
              [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"],
              [[NSFileManager defaultManager] fileExistsAtPath:@"/usr/lib/libsubstrate.dylib"]);

    QMDiagLog(@"---- load order ----");
    int n = QMDyldImageCount();
    for (int i = 0; i < n; i++) {
        const char *name = QMDyldImageName(i);
        if (!name) continue;
        if (strstr(name, "PxExt") || strstr(name, "QoSMetrics") ||
            strstr(name, "DeltaForce") || strstr(name, "substrate")) {
            QMDiagLog(@"  image[%d] %s", i, name);
        }
    }

    QMDiagLog(@"---- gate classes ----");
    const char *names[] = { "SKClient", "SKStore", "SKNetwork", "SKUDIDFlow",
                            "SKHUD", "SKOverlayVC", "UIManager", "MenuView",
                            "TPPFloatingButton", "FloatingButton", "BypassEarlyLoader" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        Class c = NSClassFromString([NSString stringWithUTF8String:names[i]]);
        if (!c) {
            QMDiagLog(@"  %-18s ABSENT", names[i]);
            continue;
        }
        Class sup = class_getSuperclass(c);
        unsigned mc = 0;
        unsigned imc = 0;
        Method *ml = class_copyMethodList(c, &mc);
        if (ml) free(ml);
        Method *iml = class_copyMethodList(object_getClass(c), &imc);
        if (iml) free(iml);
        QMDiagLog(@"  %-18s %p super=%s methods=%u classmethods=%u",
                  names[i], (void *)c, sup ? class_getName(sup) : "nil", mc, imc);
    }
}

void QMDiagDumpState(id client) {
    if (!client) {
        QMDiagLog(@"STATE        : client=nil");
        return;
    }
    QMDiagLog(@"---- client state ----");
    const char *sels[] = { "savedKey", "udidValue", "token", "sessionToken",
                           "resolvedToken", "expiryDate", "expiredAtString",
                           "packageName", "lastFailCode", "packagePayload",
                           "devicePayload", "paidChallenge" };
    for (size_t i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        SEL s = sel_registerName(sels[i]);
        id v = nil;
        if ([client respondsToSelector:s]) {
            v = ((id (*)(id, SEL))[client methodForSelector:s])(client, s);
        }
        QMDiagLog(@"  %-18s = %@", sels[i], QMDescribe(v));
    }
    const char *bools[] = { "hasValidatedSession", "authWallRequired", "validating",
                            "silentRevalidating", "successCardShown", "hideUI" };
    for (size_t i = 0; i < sizeof(bools) / sizeof(bools[0]); i++) {
        SEL s = sel_registerName(bools[i]);
        BOOL v = NO;
        if ([client respondsToSelector:s]) {
            v = ((BOOL (*)(id, SEL))[client methodForSelector:s])(client, s);
        }
        QMDiagLog(@"  %-18s = %s", bools[i], v ? "YES" : "NO");
    }
    SEL pc = sel_registerName("paidCount");
    if ([client respondsToSelector:pc]) {
        short v = ((short (*)(id, SEL))[client methodForSelector:pc])(client, pc);
        QMDiagLog(@"  %-18s = %d", "paidCount", (int)v);
    }
}

void QMDiagDumpFail(id code, id message, BOOL silent) {
    QMDiagLog(@"FAIL swallowed : code=%@ silent=%d msg=%@",
              QMDescribe(code), (int)silent, QMDescribe(message));
}
