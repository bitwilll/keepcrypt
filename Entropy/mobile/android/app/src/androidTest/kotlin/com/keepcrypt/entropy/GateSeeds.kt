package com.keepcrypt.entropy

/**
 * vectors/kcr.json's public gate seeds as the journeys use them (JourneyTest, SnapshotDrillTest): each
 * seed's dice-only rolls (a pattern repeated), its Seal ID, seal tag T and seal code as registered, and
 * its words (its mnemonic field). The words are compared in-process with the pages the app holds and
 * never printed or put in a selector (lead decision M5-68 (e)); the rest is public.
 */
internal object GateSeeds {
    /** dice-50-words12's rolls: 123456 repeated (50 for 12 words). */
    const val DICE_50_ROLLS = "123456"
    const val DICE_50_SEAL_ID = "YVM9CPP3"
    const val DICE_50_SEAL_CODE = "B98KT954NNYSS6APNPZWCYY0VA"
    val DICE_50_WORDS = listOf(
        "unveil", "nice", "picture", "region", "tragic", "fault", "cream", "strike", "tourist", "control",
        "recipe", "tourist",
    )

    /** dice-99-words12's and dice-99-words24's rolls: 654321 repeated (99). */
    const val DICE_99_ROLLS = "654321"
    const val DICE_99_SEAL_ID = "9FHYMCQA"
    const val DICE_99_TAG = "4be3ea32eaee361d4ba6ce2135459510ccd0b7fd869121425c068b4538657f14"
    const val DICE_99_SEAL_CODE = "15ZHX4W7AVW8VRSNJVXZEHQ2SV"
    val DICE_99_WORDS = listOf(
        "various", "tape", "mercy", "east", "hair", "tragic", "arrest", "together", "day", "tag", "afford", "occur",
    )

    /** dice-99-words24: the same 99 rolls, 24 words. */
    const val DICE_99_24_SEAL_ID = "RXDANDFR"
    const val DICE_99_24_SEAL_CODE = "C3ER95M4JV2N4TCPBRRG41J74W"
    val DICE_99_24_WORDS = listOf(
        "various", "tape", "mercy", "east", "hair", "tragic", "arrest", "together", "day", "tag", "afford",
        "obvious", "devote", "violin", "coil", "conduct", "salmon", "kidney", "anchor", "monkey", "cruel", "truth",
        "dash", "smart",
    )
}
