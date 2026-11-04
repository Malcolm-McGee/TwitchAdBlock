#pragma once
#import <UIKit/UIKit.h>

// All windows across every connected UIWindowScene (multi-window safe).
NSArray<UIWindow *> *twab_allWindows(void);
// Width of the foreground key window — use instead of UIScreen.mainScreen,
// which on iPhone Duo is the whole panel even in Split View.
CGFloat twab_activeWindowWidth(void);
// Lines for the Diagnostics screen's "Display" section.
NSArray<NSString *> *twab_displayDiagnostics(void);
