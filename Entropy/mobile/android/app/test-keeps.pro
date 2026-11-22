# What the instrumented tests take from the shipped app (tasks/todo.md, M7 D2b, M7-10). The test APK
# leaves out every library the app also carries and uses the app's copy, so R8 must keep what the
# tests call there, or the runner itself fails to start (NoClassDefFoundError: kotlin.LazyKt, the
# local kc37 run of 2026-11-22). Found by comparing the test APK's class and method references with
# the shrunk app's definitions: 37 classes (Kotlin's standard library, the kotlinx library Compose
# brings, androidx.concurrent.futures, Guava's ListenableFuture) and 13 methods (below);
# scripts/android-link-check.py now checks it on every build. The shipped APK
# carries these too, so the tests run on its bytes; library code is not judged by the dex scan
# (Q59 (b)).
-keep class kotlin.** { *; }
-keep class kotlinx.** { *; }
-keep class androidx.concurrent.futures.** { *; }
-keep interface com.google.common.util.concurrent.ListenableFuture { *; }
-keep class androidx.tracing.Trace { *; }
-keep class androidx.compose.ui.platform.ViewRootForTest { *; }
-keep class androidx.compose.ui.platform.ViewRootForTest$Companion { *; }
-keep class androidx.compose.ui.semantics.SemanticsOwner { *; }
-keep class androidx.compose.ui.semantics.SemanticsOwnerKt { *; }
-keep class androidx.compose.ui.text.TextLayoutResult { *; }
