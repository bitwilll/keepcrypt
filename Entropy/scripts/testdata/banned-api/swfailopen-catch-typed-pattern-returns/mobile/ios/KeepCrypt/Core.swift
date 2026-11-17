do {
    try core.call(op)
} catch let error as WireError where error.isSoft {
    return
}
