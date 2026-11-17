do { try core.call(op) } catch { if fatal { Ceremony.halt(.core) } }
