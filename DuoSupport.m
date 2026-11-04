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
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
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

// ─── Full-width video on iPhone Duo ─────────────────────────────────────────
// On the Duo's inner display the status bar lives in a column on the right,
// and iOS keeps that column out of the app's safe area while the status bar
// is showing. YouTube hides the status bar for full-screen video, so its
// video runs edge to edge; Twitch's player doesn't, so its video stops short
// of the column. We watch the video layers themselves (no Twitch class names,
// which change between versions): when one fills a landscape window, every
// view controller in that window reports prefersStatusBarHidden = YES, the
// column is released and Twitch's layout grows into it.

@interface TWABWeakLayer : NSObject
@property (nonatomic, weak) CALayer *layer;
@end
@implementation TWABWeakLayer
@end

static char twab_fullVideoKey;
static NSMutableSet<Class> *twab_statusBarHooked;
static NSMutableArray<NSString *> *twab_videoHooksFound;

static UIWindow *twab_windowForLayer(CALayer *layer) {
    for (CALayer *l = layer; l; l = l.superlayer) {
        id d = l.delegate;
        if ([d isKindOfClass:UIWindow.class]) return d;
        if ([d isKindOfClass:UIView.class]) return ((UIView *)d).window;
    }
    return nil;
}

// A video layer counts as "full screen" when the window is landscape and the
// layer covers most of it. Before the status bar hides, Twitch's player is
// ~91% of the window's width (the rest is the status column), hence 0.85.
static BOOL twab_layerIsFullVideo(CALayer *layer, UIWindow *w) {
    if (!layer || !w || layer.hidden || layer.opacity < 0.01) return NO;
    if (twab_windowForLayer(layer) != w) return NO;
    CGSize ws = w.bounds.size;
    if (ws.width <= ws.height) return NO;
    CGRect r = [layer convertRect:layer.bounds toLayer:w.layer];
    return r.size.width >= ws.width * 0.85 && r.size.height >= ws.height * 0.6;
}

static BOOL twab_windowHasFullVideo(UIWindow *w) {
    if (!w) return NO;
    TWABWeakLayer *box = objc_getAssociatedObject(w, &twab_fullVideoKey);
    return twab_layerIsFullVideo(box.layer, w);
}

static void twab_hookStatusBarClass(Class c);

static void twab_walkVCs(UIViewController *vc, void (^f)(UIViewController *)) {
    if (!vc) return;
    f(vc);
    for (UIViewController *child in vc.childViewControllers) twab_walkVCs(child, f);
    if (vc.presentedViewController && vc.presentedViewController.presentingViewController == vc)
        twab_walkVCs(vc.presentedViewController, f);
}

static void twab_refreshStatusBar(UIWindow *w) {
    dispatch_async(dispatch_get_main_queue(), ^{
        // Hook every controller class in the window first (Twitch's Swift
        // controllers override prefersStatusBarHidden, so a UIViewController-
        // level hook alone wouldn't be asked), then ask UIKit to re-query.
        twab_walkVCs(w.rootViewController, ^(UIViewController *vc) {
            twab_hookStatusBarClass(vc.class);
        });
        twab_walkVCs(w.rootViewController, ^(UIViewController *vc) {
            [vc setNeedsStatusBarAppearanceUpdate];
        });
    });
}

static void twab_noteVideoLayer(CALayer *layer) {
    UIWindow *w = twab_windowForLayer(layer);
    if (!w) return;
    BOOL before = twab_windowHasFullVideo(w);
    TWABWeakLayer *box = objc_getAssociatedObject(w, &twab_fullVideoKey);
    if (twab_layerIsFullVideo(layer, w)) {
        if (!box) {
            box = [TWABWeakLayer new];
            objc_setAssociatedObject(w, &twab_fullVideoKey, box, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        box.layer = layer;
    } else if (box.layer == layer) {
        box.layer = nil;
    }
    if (twab_windowHasFullVideo(w) != before) twab_refreshStatusBar(w);
}

static void twab_hookStatusBarClass(Class c) {
    if (!c || [twab_statusBarHooked containsObject:c]) return;
    [twab_statusBarHooked addObject:c];
    SEL sel = @selector(prefersStatusBarHidden);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    BOOL (*orig)(id, SEL) = (BOOL (*)(id, SEL))method_getImplementation(m);
    IMP repl = imp_implementationWithBlock(^BOOL(UIViewController *vc) {
        if (twab_windowHasFullVideo(vc.viewIfLoaded.window)) return YES;
        return orig(vc, sel);
    });
    // Inherited → add an override on this class; own method → replace it.
    if (!class_addMethod(c, sel, repl, method_getTypeEncoding(m)))
        method_setImplementation(m, repl);
}

// Run `after` each time `sel` (a void, no-argument method) runs on `c`.
static void twab_hookAfter(Class c, SEL sel, void (*after)(id)) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    void (*orig)(id, SEL) = (void (*)(id, SEL))method_getImplementation(m);
    IMP repl = imp_implementationWithBlock(^(id self_) {
        orig(self_, sel);
        after(self_);
    });
    if (!class_addMethod(c, sel, repl, method_getTypeEncoding(m)))
        method_setImplementation(m, repl);
}

static void twab_afterLayerLayout(id layer) { twab_noteVideoLayer(layer); }
static void twab_afterViewLayout(id view) { twab_noteVideoLayer(((UIView *)view).layer); }

__attribute__((constructor)) static void twab_installFullVideo(void) {
    twab_statusBarHooked = [NSMutableSet set];
    twab_videoHooksFound = [NSMutableArray array];
    twab_hookStatusBarClass(UIViewController.class);
    // Twitch plays live streams with Amazon IVS and some video with AVKit.
    for (NSString *name in @[ @"IVSPlayerLayer", @"AVPlayerLayer" ]) {
        Class c = NSClassFromString(name);
        if (!c) continue;
        twab_hookAfter(c, @selector(layoutSublayers), twab_afterLayerLayout);
        [twab_videoHooksFound addObject:name];
    }
    Class view = NSClassFromString(@"IVSPlayerView");
    if (view) {
        twab_hookAfter(view, @selector(layoutSubviews), twab_afterViewLayout);
        [twab_videoHooksFound addObject:@"IVSPlayerView"];
    }
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
    [lines addObject:[NSString stringWithFormat:
        @"Full-width video: watching %@ — hides the status bar when video fills a landscape window",
        twab_videoHooksFound.count ? [twab_videoHooksFound componentsJoinedByString:@", "]
                                   : @"nothing (no video player classes found)"]];
    return lines;
}
