// QMDiag.h — instrumentation for QoSMetrics.
//
// Everything the shim installs or decides lands in a log file, so a failing
// bypass can be diagnosed from the log alone instead of guesswork. NSLog is
// mirrored to the file because early boot messages are frequently lost.
//
// Log path, first writable wins:
//   /var/mobile/Library/Logs/QoSMetrics.log          (jailbroken, rootful)
//   /var/jb/var/mobile/Library/Logs/QoSMetrics.log   (rootless)
//   <app container>/Documents/QoSMetrics.log         (TrollStore / Esign)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

void QMDiagOpen(void);
void QMDiagLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
void QMDiagNote(NSString *tag, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);

// Read the IMP back after installing and confirm it is ours. This is the only
// honest answer to "did the hook actually land" — MSHookMessageEx returns void
// and a missing selector fails silently.
BOOL QMDiagVerifyHook(Class cls, SEL sel, IMP expected, const char *label);

void QMDiagDumpEnvironment(void);
void QMDiagDumpState(id client);
void QMDiagDumpFail(id code, id message, BOOL silent);

NSString *QMDiagPath(void);
