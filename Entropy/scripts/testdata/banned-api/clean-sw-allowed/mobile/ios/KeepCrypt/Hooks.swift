#if KC_TEST_HOOKS
// The capture layers' test hooks, compiled only where the test targets set the condition.
enum Hooks {
    static var captured = false
}
#endif
