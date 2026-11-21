func call(_ op: UInt32) -> Data {
    do {
        return try core.call(op)
    } catch {
        Ceremony.halt(.core)
    }
}

func decode(_ data: Data) throws -> Reply {
    do {
        return try Reply(data)
    } catch let error as WireError where error.isTruncated {
        throw error
    } catch {
        Ceremony.halt(.wire);
    }
}
