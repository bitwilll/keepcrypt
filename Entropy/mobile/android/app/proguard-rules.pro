# R8 for the release build type (tasks/todo.md, M7 D2b, lead decision M7-10): shrinking alone.
#
# -dontoptimize: R8's optimizer may drop a write it proves dead, and the wipes that overwrite a
# secret array with zeros before it is let go are exactly such writes (rule 5). Shrinking removes
# whole classes and members nothing reaches, never a statement in a kept method.
# -dontobfuscate: the APK keeps its names, so the auditor, dexdump and banned-api-check.sh --apk read
# the same classes as the source.
-dontoptimize
-dontobfuscate

# The app's own code, whole: the instrumented tests run against this release build (testBuildType
# release) and call into it; libkeepcrypt.so finds Native.call by its JNI name.
-keep class com.keepcrypt.** { *; }
