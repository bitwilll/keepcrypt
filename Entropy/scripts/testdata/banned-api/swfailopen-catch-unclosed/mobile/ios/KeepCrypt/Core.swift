do { try core.call(op) } catch {
    Ceremony.halt(.core)
