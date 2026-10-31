package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Leaving the app on every screen of the walk (tasks/todo.md, Stage U's U2e; docs/mobile-apps.md:34, Q57,
 * Q75), over the real slot. On a Protected screen and during a long call, leaving discards at once, with
 * the Left notice ("Working..." once its call's reply comes; the start-up self-test, which holds no
 * session, back to First launch with nothing to say). On a Public screen the privacy cover goes up and
 * the background time starts: 59 s away keeps everything, and the return keeps the cover until a tap,
 * which only uncovers; 61 s away wipes what is held, with the Background notice, whether the timers ran
 * while away or the process was frozen and the wipe comes at the return, before anything shows; a Public
 * screen that holds nothing keeps its place 61 s away. The words' states the walk's screens do not name
 * (Walk.states) are Protected, their privacy gates included, as built: whether a gate is a Public screen is
 * the owner's open Q82. Every long call (a start, the self-test, the dice's Done, a scanned go-ahead QR's
 * check, the backup's encryption and its check, a snapshot's and a backup's read and load, a backup's
 * opening) is discarded at once by a leave or by going online while it runs, its screen kept until its
 * reply, then the start screen with the notice; the self-test, which holds no session, starts again from
 * First launch after a leave, and going online, which nothing needs before Go offline, leaves it to pass
 * on to Go offline, each with nothing to say. The model's isProtected is
 * Walk.protected, the docs' list. Each walk leaves the slot at home (wipeAll after it).
 */
class LeavingTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    @Test
    fun leavingAProtectedScreenOrALongCallDiscardsAtOnceAndAPublicOneIsCovered() {
        for (screen in Walk.screens) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            val held = rig.model.held.value
            rig.model.appLeft()
            when {
                screen == Screen.SelfTest -> {
                    assertEquals(Screen.SelfTest, rig.screen, "$name: until the self-test's reply")
                    rig.worker.run()
                    assertEquals(Screen.FirstLaunch, rig.screen, "$name: the self-test left runs again from First launch")
                    assertNull(rig.model.state.value.notice, "$name: no session was held")
                }
                screen == Screen.Working -> {
                    assertEquals(Screen.Working, rig.screen, "$name: until the call's reply")
                    rig.worker.run()
                    rig.assertDiscarded(Notice.Left, name)
                    assertTrue(Core.selfTest() is Reply.Done, "$name: the call left something in core")
                }
                screen in Walk.protected -> {
                    rig.assertDiscarded(Notice.Left, "$name: leaving a Protected screen")
                    rig.assertNothingSecretShown(name)
                    assertTrue(Core.selfTest() is Reply.Done, "$name: leaving left something in core")
                }
                else -> {
                    val state = rig.model.state.value
                    assertEquals(screen, state.screen, "$name: leaving a Public screen")
                    assertEquals(Overlay.Cover, state.overlay, "$name: the privacy cover")
                    assertNull(state.notice, name)
                    assertEquals(held, rig.model.held.value, "$name: leaving a Public screen kept what is held")
                }
            }
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun theProtectedScreensAreTheDocsList() {
        assertEquals(Walk.protected, Walk.screens.filter(::isProtected).toSet(), "isProtected against docs/mobile-apps.md:34")
    }

    @Test
    fun leavingTheWordsStatesTheWalksScreensDoNotNameDiscardsAtOnce() {
        for ((what, reach) in Walk.states) {
            val rig = reach()
            rig.model.appLeft()
            rig.assertDiscarded(Notice.Left, "$what: leaving")
            rig.assertNothingSecretShown(what)
            assertTrue(Core.selfTest() is Reply.Done, "$what: leaving left something in core")
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    /**
     * Each long call the model makes, started from where the model makes it and held on the worker: its
     * name, and a fresh Rig on its screen with the call waiting.
     */
    private val longCalls: List<Pair<String, () -> Rig>> = listOf(
        "the start" to { Walk.to(Screen.Working) },
        "the self-test" to { Walk.to(Screen.SelfTest) },
        "the dice's Done" to {
            val rig = Walk.to(Screen.Dice)
            rig.roll(99)
            rig.model.diceDone()
            rig
        },
        "a scanned go-ahead QR's check" to {
            val rig = Walk.to(Screen.Scan)
            rig.model.onGoAheadText(kcrProofUr("clear-empty-bucket"))
            rig
        },
        "the backup's encryption" to {
            val rig = Walk.to(Screen.BackupPassphrase)
            val words = rig.passphraseWords().toMutableList()
            rig.model.nextPage()
            words.addAll(rig.passphraseWords())
            rig.model.passphraseWritten()
            repeat(2) {
                val state = rig.model.state.value
                rig.answer(words[checkNotNull(state.challenge).questions[state.page].position - 1])
            }
            rig
        },
        "the saved backup's check" to {
            val rig = Walk.to(Screen.BackupSave)
            rig.model.saveBackup(FakePickers())
            rig.model.backupPlaced(FakePlace())
            rig.model.appResumed()
            rig
        },
        "a snapshot's read and load" to {
            val rig = Walk.to(Screen.Home)
            val bytes = kcrSnapshot("with-dice-50")
            rig.model.loadSnapshot(FakePickers())
            rig.model.snapshotPicked(FakeFile("with-dice-50.kcr", bytes.size.toLong(), bytes))
            rig.model.appResumed()
            rig
        },
        "a backup's read" to {
            val rig = Walk.to(Screen.Home)
            val saved = SavedBackup.shared
            rig.model.checkBackup(FakePickers())
            rig.model.backupPicked(FakeFile(SavedBackup.NAME, saved.file.size.toLong(), saved.file))
            rig.model.appResumed()
            rig
        },
        "a backup's opening" to {
            val rig = Walk.to(Screen.BackupCheckEntry)
            for (word in SavedBackup.shared.passphrase) {
                rig.press(word.take(4))
                rig.model.entryTyped()
            }
            rig
        },
    )

    @Test
    fun aLeaveOrGoingOnlineDuringEveryLongCallDiscardsIt() {
        SavedBackup.shared
        for ((call, start) in longCalls) {
            for (online in listOf(false, true)) {
                val what = call + if (online) ", going online" else ", leaving"
                val rig = start()
                val busy = rig.screen
                assertTrue(isWorking(busy) && rig.worker.waiting > 0, "$what: the call waits behind its screen")
                if (online) rig.offline.set(false) else rig.model.appLeft()
                assertEquals(busy, rig.screen, "$what: its screen until its reply")
                rig.worker.run()
                if (busy == Screen.SelfTest) {
                    assertEquals(if (online) Screen.GoOffline else Screen.FirstLaunch, rig.screen, what)
                    assertNull(rig.model.state.value.notice, "$what: no session was held")
                } else {
                    rig.assertDiscarded(if (online) Notice.Offline else Notice.Left, what)
                    rig.assertNothingSecretShown(what)
                    assertNull(rig.model.state.value.loaded, "$what: nothing loaded")
                }
                assertTrue(Core.selfTest() is Reply.Done, "$what: the call left something in core")
                assertTrue(Core.wipeAll() is Reply.Done)
            }
        }
    }

    @Test
    fun sixtySecondsAwayFromAPublicScreenWipesWhatIsHeldAndFiftyNineKeepIt() {
        for (screen in Walk.screens.filterNot { it in Walk.protected || isWorking(it) }) {
            val name = screenId(screen)
            val kept = Walk.to(screen)
            val held = kept.model.held.value
            val page = kept.model.state.value.page
            kept.model.appLeft()
            kept.clock.now += Timers.BACKGROUND_MILLIS - 1_000
            kept.model.tick()
            kept.model.appReturned()
            assertEquals(screen, kept.screen, "$name: 59 s away")
            assertEquals(held, kept.model.held.value, "$name: 59 s away kept what is held")
            assertEquals(Overlay.Cover, kept.model.state.value.overlay, "$name: back within 60 s, the cover stays")
            kept.model.dismissOverlay()
            assertEquals(screen, kept.screen, "$name: the tap only uncovers")
            assertNull(kept.model.state.value.overlay, "$name: the tap uncovered")
            assertEquals(page, kept.model.state.value.page, name)
            assertTrue(Core.wipeAll() is Reply.Done)

            for (frozen in listOf(false, true)) {
                val what = name + if (frozen) ": 61 s away, frozen" else ": 61 s away"
                val away = Walk.to(screen)
                away.model.appLeft()
                away.clock.now += Timers.BACKGROUND_MILLIS + 1_000
                if (!frozen) away.model.tick()
                away.model.appReturned()
                if (held) {
                    away.assertDiscarded(Notice.Background, what)
                    away.assertNothingSecretShown(what)
                    assertTrue(Core.selfTest() is Reply.Done, "$what: the wipe left something in core")
                } else {
                    assertEquals(screen, away.screen, "$what: nothing held, nothing to wipe")
                    assertNull(away.model.state.value.notice, what)
                    assertFalse(away.model.held.value, what)
                }
                assertTrue(Core.wipeAll() is Reply.Done)
            }
        }
    }
}
