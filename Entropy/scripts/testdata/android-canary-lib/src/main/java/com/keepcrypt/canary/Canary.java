// The canary library's one class (tasks/todo.md, M5 group 5): a com.keepcrypt class that rolls a die
// with java.util.Random, as code that breaks rule 1 would. Never shipped and in no real build
// (scripts/testdata/android-canary-lib/build.gradle.kts). The canary APK carries it, R8 being off,
// and scripts/banned-api-check.sh --apk must refuse it with a DexRef hit: the dex reference scan's
// positive control on the real dexdump's output. Java, so that the JDK's javac compiles it and the
// canary build resolves nothing for it.
package com.keepcrypt.canary;

public final class Canary {
    private Canary() {
    }

    public static int roll() {
        return new java.util.Random().nextInt(6) + 1;
    }
}
