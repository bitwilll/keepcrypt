// The Swift CeremonyModel's halt: it wipes the session and ends the app, and never returns.
enum Ceremony {
    static func halt(_ reason: Halt) -> Never {
        exit(1)
    }
}
