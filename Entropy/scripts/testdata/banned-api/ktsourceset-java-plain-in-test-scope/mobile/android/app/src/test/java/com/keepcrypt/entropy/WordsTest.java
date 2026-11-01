package com.keepcrypt.entropy;

// A JVM test in Java, in plain letters, in a test source set: still a Java source.
public final class WordsTest {
    @org.junit.Test
    public void twelveWords() {
        org.junit.Assert.assertEquals(12, Words.count());
    }
}
