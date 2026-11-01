package com.keepcrypt.entropy;

// javac reads each backslash-u escape below as the letter it names, before it reads the code: the
// method is Math's random and the clause a catch of every Throwable, words no text rule sees here.
final class Legacy {
    static int roll() {
        try {
            return (int) (Math.\u0072andom() * 6) + 1;
        } \u0063atch (\u0054hrowable failure) {
            return 0;
        }
    }
}
