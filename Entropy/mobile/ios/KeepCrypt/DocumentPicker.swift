// The document pickers (tasks/todo.md, M6 items D4, D6 and D7; docs/mobile-apps.md, "Reading a snapshot" and
// "Encrypted backup only"; rule 8: the only files read are .kcr snapshots and .age backups, the only file
// written the backup): the gate's one file for the backup's write (D6). In D4, Load registry snapshot:
// SwiftUI's fileImporter (Screens.swift) offers any data file (the model refuses a name not ending in .kcr,
// and a size past core's limit, before any byte is read, as Android's), and the file it gives is read here,
// once, on the model's worker, into memory alone: nothing is copied, cached or kept, and no access to the
// place is kept past the read.

import Foundation
import SwiftUI

/// The pickers the model's entry points open (Android's DocumentPickers): each sets what Screens presents.
final class ScreenPickers: ObservableObject, DocumentPickers {
    /// Load registry snapshot's open picker is up.
    @Published var snapshotOpen = false

    /// The backup's save picker: D6's.
    func create(name: String) {}

    /// Check a backup's open picker: D7's.
    func openBackup() {}

    func openSnapshot() {
        snapshotOpen = true
    }
}

/// A file the open picker gave: its name, its size as the file system reports it (nil where it cannot), and
/// its bytes, read once, at most limit + 1 (one past limit says it is larger), into a Secret, the buffer
/// they came through wiped.
final class PickedURLFile: PickedFile {
    private let url: URL
    let name: String?
    let size: Int64?

    init(_ url: URL) {
        self.url = url
        name = url.lastPathComponent
        size = PickedURLFile.sizeOf(url)
    }

    /// The file's size, or nil: stat on the picked place, inside its security scope.
    private static func sizeOf(_ url: URL) -> Int64? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped { url.stopAccessingSecurityScopedResource() }
        }
        var info = stat()
        let found = url.withUnsafeFileSystemRepresentation { path -> Bool in
            guard let path else { return false }
            return stat(path, &info) == 0
        }
        guard found, info.st_size >= 0 else { return nil }
        return Int64(info.st_size)
    }

    /// Called on the model's worker: one read of at most limit + 1 bytes through a handle that closes as it
    /// goes, the bytes copied once into a Secret and the Data they came in wiped.
    func read(limit: Int) -> Secret? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped { url.stopAccessingSecurityScopedResource() }
        }
        let handle = url.withUnsafeFileSystemRepresentation { path -> FileHandle? in
            guard let path else { return nil }
            return FileHandle(forReadingAtPath: String(cString: path))
        }
        guard let handle else { return nil }
        var data = handle.readData(ofLength: limit + 1)
        let file = data.withUnsafeBytes { raw -> Secret? in
            guard let base = raw.baseAddress else { return raw.isEmpty ? Secret(taking: []) : nil }
            return Secret(copying: base, count: raw.count)
        }
        data.resetBytes(in: data.startIndex..<data.endIndex)
        return file
    }
}
