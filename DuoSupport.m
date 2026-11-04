// DuoSupport.m
// Helpers that keep TwitchMods' own UI correct on iPhone Duo, where the app
// can have several windows (Split View, a second Safari-style window) and
// resizes live as the phone opens, closes or tilts. Also feeds the
// "Display" section of the Diagnostics screen.
//
// Whether Twitch fills the Duo's inner display at all is decided by the SDK
// the Twitch binary was linked against, not by anything at runtime — see
// `inject_ipa.py --duo`. The Diagnostics lines below show which mode is live.

#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import "DuoSupport.h"

// Every window in every connected scene. UIApplication.windows is deprecated
// and only reliable for a single-scene app.
NSArray<UIWindow *> *twab_allWindows(void) {
    NSMutableArray<UIWindow *> *out = [NSMutableArray array];
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            [out addObjectsFromArray:((UIWindowScene *)scene).windows];
        }
    }
    if (out.count == 0) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [out addObjectsFromArray:UIApplication.sharedApplication.windows];
#pragma clang diagnostic pop
    }
    return out;
}

// Width of the window the user is actually looking at (the foreground,
// key one), not the whole physical screen: on the Duo the screen is the
// unfolded panel even while Twitch only has half of it in Split View.
CGFloat twab_activeWindowWidth(void) {
    UIWindow *best = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            if (scene.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) return w.bounds.size.width;
                if (!best) best = w;
            }
        }
    }
    if (best) return best.bounds.size.width;
    UIWindow *any = twab_allWindows().firstObject;
    return any ? any.bounds.size.width : 375;
}

static NSString *twab_fmtVersion(uint32_t v) {
    if (v == 0) return @"unknown";
    uint32_t major = v >> 16, minor = (v >> 8) & 0xFF, patch = v & 0xFF;
    return patch ? [NSString stringWithFormat:@"%u.%u.%u", major, minor, patch]
                 : [NSString stringWithFormat:@"%u.%u", major, minor];
}

// SDK the running Twitch binary says it was linked against. dyld reads this
// from LC_BUILD_VERSION, which is what `inject_ipa.py --duo` bumps.
static uint32_t twab_programSDK(void) {
    uint32_t (*fn)(void) = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "dyld_get_program_sdk_version");
    return fn ? fn() : 0;
}

static NSString *twab_sizeClass(UIUserInterfaceSizeClass c) {
    switch (c) {
        case UIUserInterfaceSizeClassCompact: return @"compact";
        case UIUserInterfaceSizeClassRegular: return @"regular";
        default: return @"?";
    }
}

NSArray<NSString *> *twab_displayDiagnostics(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    uint32_t sdk = twab_programSDK();
    BOOL duoReady = sdk >= ((27u << 16) | (1u << 8));
    [lines addObject:[NSString stringWithFormat:@"App linked against iOS %@ — %@",
        twab_fmtVersion(sdk),
        duoReady ? @"iPhone Duo full-screen ready"
                 : @"iPhone Duo shows this app in a phone-sized window (rebuild with --duo)"]];

    NSUInteger windowScenes = 0;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            windowScenes++;
            UIWindowScene *ws = (UIWindowScene *)scene;
            CGSize win = ws.coordinateSpace.bounds.size;
            CGSize scr = ws.screen.bounds.size;
            UITraitCollection *t = ws.traitCollection;
            NSString *state = scene.activationState == UISceneActivationStateForegroundActive
                ? @"active" : @"background";
            [lines addObject:[NSString stringWithFormat:
                @"Window %lu (%@): %.0f×%.0f pt of %.0f×%.0f screen, %@ w / %@ h, @%.0fx",
                (unsigned long)windowScenes, state, win.width, win.height,
                scr.width, scr.height,
                twab_sizeClass(t.horizontalSizeClass), twab_sizeClass(t.verticalSizeClass),
                t.displayScale]];
        }
    }
    if (windowScenes == 0) [lines addObject:@"No window scenes connected"];
    return lines;
}
