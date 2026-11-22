# R8 for the instrumented-test APKs (tasks/todo.md, M7 D2b): they ship nowhere, so R8 changes
# nothing in them; it only links them against the shrunk app. androidx.test names Error Prone's
# compile-time annotations, which are in no APK.
-dontshrink
-dontoptimize
-dontobfuscate
-dontwarn com.google.errorprone.annotations.**
