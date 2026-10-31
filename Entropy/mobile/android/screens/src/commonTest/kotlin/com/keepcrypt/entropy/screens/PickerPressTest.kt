package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One press opens one picker (tasks/todo.md, Stage U's U2c), over the real slot: the system's pickers
 * open over the app as activities of their own, one for each launch, so a double tap on Save, Check a
 * backup or Load registry snapshot, or one on each of Home's two, made before the first picker covers
 * the app, opened two, and the second's answer came after the first's. While a picker the app opened is
 * up, a press that would open one opens none; its answer (a place, a file or none, a late one after
 * Home has gone too) or the activity's next resume (an answer lost) frees the buttons again, and the
 * picker's stop is no leaving. Each test leaves the slot at home.
 */
class PickerPressTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    @Test
    fun aSecondPressOnSaveOpensNoSecondPickerUntilTheFirstAnswers() {
        val rig = Walk.to(Screen.BackupSave)
        val pickers = FakePickers()
        rig.model.saveBackup(pickers)
        rig.model.saveBackup(pickers)
        assertEquals(1, pickers.created.size, "a double tap on Save opened one picker")
        rig.model.backupPlaced(null)
        assertEquals(Screen.BackupSave, rig.screen, "no place: the save screen stays")
        rig.model.saveBackup(pickers)
        assertEquals(2, pickers.created.size, "the answer freed Save")
    }

    @Test
    fun homesTwoPickersOpenOneAtATime() {
        val rig = Walk.to(Screen.Home)
        val pickers = FakePickers()
        rig.model.checkBackup(pickers)
        rig.model.checkBackup(pickers)
        rig.model.loadSnapshot(pickers)
        assertEquals(1, pickers.opens, "a double tap on Check a backup opened one picker")
        assertEquals(0, pickers.snapshotOpens, "Load registry snapshot opened a second picker over the first")
        rig.model.backupPicked(null)
        rig.model.loadSnapshot(pickers)
        rig.model.checkBackup(pickers)
        assertEquals(1, pickers.snapshotOpens, "the answer freed Load registry snapshot")
        assertEquals(1, pickers.opens, "Check a backup opened a second picker over the snapshot's")
        rig.model.snapshotPicked(null)
        rig.model.checkBackup(pickers)
        assertEquals(2, pickers.opens, "the snapshot picker's answer freed Check a backup")
    }

    @Test
    fun aResumeWithNoAnswerFreesThePickersButtons() {
        val rig = Walk.to(Screen.Home)
        val pickers = FakePickers()
        rig.model.checkBackup(pickers)
        rig.model.appLeft()
        rig.model.appReturned()
        rig.model.appResumed()
        assertEquals(Screen.Home, rig.screen, "the picker's stop was no leaving")
        assertNull(rig.model.state.value.overlay, "the picker's stop brought no cover")
        rig.model.checkBackup(pickers)
        assertEquals(2, pickers.opens, "a resume with the answer lost freed Check a backup")
    }

    @Test
    fun aLateAnswerFreesThePickersButtons() {
        val rig = Walk.to(Screen.Home)
        val pickers = FakePickers()
        rig.model.checkBackup(pickers)
        rig.offline.set(false)
        assertEquals(Screen.GoOffline, rig.screen, "going online while the picker is up: Home needs the phone offline")
        rig.model.backupPicked(null)
        rig.offline.set(true)
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen)
        rig.model.checkBackup(pickers)
        assertEquals(2, pickers.opens, "the late answer, with no resume, freed Check a backup")
    }
}
