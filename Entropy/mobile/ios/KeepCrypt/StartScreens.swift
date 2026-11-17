// The screens from the start to the dice (tasks/todo.md, M6 item D3; Android's FirstLaunch.kt and
// StartScreens.kt; docs/mobile-apps.md, "Screens and user flow", steps 1-8): First launch, Self-test, Go
// offline, Home, Length, Device entropy, Commitment and Dice, each Public, drawn with the kit in Android's
// wording (Texts.swift), order and identifiers, and each handing its presses to the ceremony model, which
// ignores a press its screen no longer shows. Each screen's heading is its title (Screen.swift) where
// Android's is.

import SwiftUI

/// The first screen, shown on every start before any core call (lead decision M5-50): what the app does,
/// what no app can stop, that the Pi is the device for life savings, and that every build is a 0.0.0
/// development build. Nothing records that it was read (rule 8), so it shows again on the next start. Its
/// Continue runs the start-up self-test, then Go offline.
struct FirstLaunchScreen: View {
    let testRegistry: Bool
    let onContinue: () -> Void

    var body: some View {
        KitScreen(Screen.firstLaunch.id, testRegistry: testRegistry) {
            Title(appName)
            Gap(16)
            KitText(developmentBuild, style: .warning)
            KitText(StartTexts.firstLaunchMakes)
            KitText(StartTexts.firstLaunchPi)
            KitText(StartTexts.firstLaunchCannotStop)
            KitText(StartTexts.firstLaunchOffline)
        } actions: {
            KitButton(StartTexts.continueButton, id: "first_launch_continue", action: onContinue)
        }
    }
}

/// The self-test's screen (docs/mobile-apps.md, step 2; the Pi's boot screen): core's known-answer tests
/// run behind it, and it takes no input.
struct SelfTestScreen: View {
    let testRegistry: Bool

    var body: some View {
        KitScreen(Screen.selfTest.id, testRegistry: testRegistry) {
            Title(appName)
            Gap(16)
            Heading(Screen.selfTest.title)
            KitText(StartTexts.selfTestRunning)
            KitText(StartTexts.selfTestFailure, style: .small)
        }
    }
}

/// Go offline (docs/mobile-apps.md, step 3; Q57): the offline check's reading (no usable path, C5) and
/// Start, disabled while a path is usable. The iPhone opens no airplane-mode settings (D3's plan, (1)).
struct GoOfflineScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onStart: () -> Void

    var body: some View {
        KitScreen(Screen.goOffline.id, testRegistry: testRegistry) {
            Heading(Screen.goOffline.title)
            KitText(StartTexts.goOfflineNeeds)
            Gap(8)
            KitText(state.offline ? StartTexts.pathNone : StartTexts.pathUsable, id: "network_state", live: true)
            if !state.offline {
                KitText(StartTexts.startDisabled, style: .small)
            }
        } actions: {
            KitButton(StartTexts.start, id: "start", enabled: state.offline, action: onStart)
        }
    }
}

/// Home (docs/mobile-apps.md, step 4): New seed, Dice-only seed, Check a backup, Load registry snapshot and
/// About (lead decision M5-48); why a file Check a backup or Load registry snapshot was given was not
/// opened, when it was not; and the registry snapshot loaded, or that none is. Check a backup, Load
/// registry snapshot and About are drawn disabled until their screens come (D4, D7; D3's plan, (2)).
struct HomeScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onNewSeed: () -> Void
    let onDiceOnly: () -> Void

    var body: some View {
        KitScreen(Screen.home.id, testRegistry: testRegistry) {
            Title(appName)
            if let refusal = state.fileRefusal {
                KitText(fileRefusalText(refusal), style: .warning, id: "file_refusal", live: true)
            }
            Gap(16)
            KitText(StartTexts.homeModes, style: .small)
            KitText(homeSnapshotLine(state.loaded), style: .small, id: "home_snapshot")
        } actions: {
            KitButton(StartTexts.newSeed, id: "new_seed", action: onNewSeed)
            KitButton(StartTexts.diceOnlySeed, id: "dice_only_seed", action: onDiceOnly)
            KitButton(StartTexts.checkBackup, id: "check_backup", enabled: false) {}
            KitButton(StartTexts.loadSnapshot, id: "load_snapshot", enabled: false) {}
            KitButton(StartTexts.about, id: "show_about", enabled: false) {}
        }
    }
}

/// Length (docs/mobile-apps.md, step 5): 12 words, the default, or 24.
struct LengthScreen: View {
    let testRegistry: Bool
    let onWords: (Words) -> Void

    var body: some View {
        KitScreen(Screen.length.id, testRegistry: testRegistry) {
            Heading(Screen.length.title)
            KitText(StartTexts.lengthNote, style: .small)
        } actions: {
            KitButton(StartTexts.twelveWords, id: "words_12") { onWords(.twelve) }
            KitButton(StartTexts.twentyFourWords, id: "words_24") { onWords(.twentyFour) }
        }
    }
}

/// Device entropy, Mixed mode only (docs/mobile-apps.md, step 6): the default mode's one sentence;
/// touches and the phone's motion go into the pool while it shows, with no credit (the model's touched
/// and its motion source), and Continue makes the commitment, which reads the phone's random source.
struct DeviceEntropyScreen: View {
    let testRegistry: Bool
    let onContinue: () -> Void

    var body: some View {
        KitScreen(Screen.deviceEntropy.id, testRegistry: testRegistry) {
            Heading(Screen.deviceEntropy.title)
            KitText(StartTexts.safeIfEither, id: "device_entropy_sentence")
            KitText(StartTexts.deviceEntropyNote, style: .small)
        } actions: {
            KitButton(StartTexts.continueButton, id: "continue", action: onContinue)
        }
    }
}

/// Commitment, Mixed mode only (docs/mobile-apps.md, step 7): C as 16 groups of 4 hex characters.
struct CommitmentScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onContinue: () -> Void

    var body: some View {
        KitScreen(Screen.commitment.id, testRegistry: testRegistry) {
            Heading(Screen.commitment.title)
            KitText(state.commitment ?? "", style: .hex, id: "commitment_hex")
            KitText(StartTexts.commitmentNote, style: .small)
        } actions: {
            KitButton(StartTexts.continueButton, id: "continue", action: onContinue)
        }
    }
}

/// Dice (docs/mobile-apps.md, step 8): the 1 to 6 pad picks a face, Confirm pushes it (disabled with no
/// face picked and at 256 rolls, where the pad is disabled too), Undo takes the last roll back; the screen
/// shows the count and the bits, never the roll history, and says when the minimum is reached, from when
/// Done makes the seed. The pick lives in the model's PadEntry, observed here, so its label redraws as it
/// changes.
struct DiceScreen: View {
    let state: UiState
    @ObservedObject var pick: PadEntry
    let testRegistry: Bool
    let onKey: (Character) -> Void
    let onConfirm: () -> Void
    let onUndo: () -> Void
    let onDone: () -> Void

    var body: some View {
        if let dice = state.dice {
            let open = dice.rolls < maxRolls
            KitScreen(Screen.dice.id, testRegistry: testRegistry) {
                Heading(Screen.dice.title)
                // The counts and their limits first, the notes under them, as Android's.
                KitText(diceText(dice.rolls, dice.minimum, dice.millibits), id: "dice_count", live: true)
                if dice.rolls >= dice.minimum {
                    KitText(StartTexts.diceMinimum, id: "dice_minimum", live: true)
                }
                if !open {
                    KitText(StartTexts.diceCap, id: "dice_cap", live: true)
                }
                KitText(StartTexts.diceHow, style: .small)
                if state.diceOnly {
                    KitText(StartTexts.diceOnly, style: .small, id: "dice_only")
                }
            } actions: {
                HStack {
                    KitText(StartTexts.picked)
                    Text(pick.length == 1 ? keyLabel(pick.keyAt(0)) : "-")
                        .font(KitType.large)
                        .foregroundColor(KitColors.text)
                        .padding(.horizontal, 16)
                        .accessibilityIdentifier("dice_pick")
                }
                DicePad(enabled: open, onKey: onKey)
                HStack(spacing: 12) {
                    KitButton(StartTexts.undo, id: "undo", enabled: dice.rolls > 0, action: onUndo)
                    KitButton(StartTexts.confirm, id: "confirm", enabled: open && pick.length == 1, action: onConfirm)
                }
                KitButton(StartTexts.done, id: "dice_done", enabled: dice.rolls >= dice.minimum, action: onDone)
            }
        }
    }
}
