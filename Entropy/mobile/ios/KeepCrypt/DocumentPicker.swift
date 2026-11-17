// The document pickers (tasks/todo.md, M6 items D4, D6 and D7; docs/mobile-apps.md, "Reading a snapshot" and
// "Encrypted backup only"; rule 8: the only files read are .kcr snapshots and .age backups, the only file
// written the backup): the gate's one file for the backup's write. In D4, Load registry snapshot: SwiftUI's
// fileImporter (Screens.swift) offers any data file (the model refuses a name not ending in .kcr, and a size
// past core's limit, before any byte is read, as Android's), and the file it gives is read here, once, on
// the model's worker, into memory alone: nothing is copied, cached or kept, and no access to the place is
// kept past the read.
//
// In D6, the backup's save (docs/mobile-apps.md, Saving steps 3-4): SwiftUI's .fileExporter with an
// in-memory document, BackupDocument, whose bytes are the model's own Secret of core's age file
// (ciphertext, made in memory), copied once into the Data the exporter writes, only when it asks to write;
// the document goes as the exporter answers. Its answer is the model's backupPlaced: the place it saved to
// (ExportedPlace: the bytes it wrote are the model's, and the file there is read back as a picked file is),
// a failure (FailedExport: the write failed), or none. What the exporter does with that Data, and any file
// it stages on the way, is the system's: ciphertext alone, which this app neither names nor can wipe (lead
// decision for D6; I2 looks at the app's container after a save and a cancel).

import Foundation
import SwiftUI
import UniformTypeIdentifiers

/// The pickers the model's entry points open (Android's DocumentPickers): each sets what Screens presents.
final class ScreenPickers: ObservableObject, DocumentPickers {
    /// Load registry snapshot's open picker is up.
    @Published var snapshotOpen = false

    /// The backup's exporter is up.
    @Published var backupOpen = false

    /// The document the exporter writes while it is up, and core's suggested name for it; nil once it
    /// answers. Not published: backupOpen presents it.
    fileprivate(set) var backup: BackupDocument?
    fileprivate(set) var backupName: String?

    /// The backup's save: the exporter, over the model's own bytes (no copy made here).
    func create(name: String, bytes: Secret) {
        backup = BackupDocument(bytes: bytes)
        backupName = name
        backupOpen = true
    }

    /// Check a backup's open picker: D7's.
    func openBackup() {}

    func openSnapshot() {
        snapshotOpen = true
    }

    /// The exporter answered: its document goes, the bytes it held kept for the place to name.
    fileprivate func exported() -> Secret? {
        let bytes = backup?.bytes
        backup = nil
        backupName = nil
        return bytes
    }
}

/// The backup as the exporter's in-memory document: the model's Secret, a binary file (an age file has no
/// type of its own, so it keeps its .age name, as Android's application/octet-stream does). It is written,
/// never read: reading one throws, and nothing in the app asks to.
struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [] }
    static var writableContentTypes: [UTType] { [.data] }

    let bytes: Secret

    init(bytes: Secret) {
        self.bytes = bytes
    }

    init(configuration: ReadConfiguration) throws {
        throw CocoaError(.featureUnsupported)
    }

    /// The bytes copied once into the Data the exporter writes, as it asks to.
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        var data = Data(count: bytes.count)
        for index in 0..<bytes.count {
            data[index] = bytes[index]
        }
        return FileWrapper(regularFileWithContents: data)
    }
}

/// The exporter over the screens (Screens.swift): presented while backupOpen, its answer handed to placed
/// (the model's backupPlaced) once, the document dropped first.
struct BackupExporter: ViewModifier {
    @ObservedObject var pickers: ScreenPickers
    let placed: (DocumentPlace?) -> Void

    func body(content: Content) -> some View {
        content.fileExporter(
            isPresented: $pickers.backupOpen, document: pickers.backup, contentTypes: [.data],
            defaultFilename: pickers.backupName,
            onCompletion: { result in
                let bytes = pickers.exported()
                switch result {
                case .success(let url):
                    placed(ExportedPlace(url, exported: bytes))
                case .failure:
                    placed(FailedExport())
                }
            },
            onCancellation: {
                _ = pickers.exported()
                placed(nil)
            })
    }
}

/// The place the exporter saved the backup to: the bytes it wrote were the ones the model hands write (the
/// same Secret), and the file there is read back once, at most limit + 1 bytes, as a picked file is.
final class ExportedPlace: DocumentPlace {
    private let url: URL
    private let exported: Secret?

    init(_ url: URL, exported: Secret?) {
        self.url = url
        self.exported = exported
    }

    func write(_ bytes: Secret) -> Bool {
        bytes === exported
    }

    func readBack(limit: Int) -> Secret? {
        readAtMost(url, limit: limit)
    }
}

/// The exporter failed: nothing was written, and nothing reads back.
final class FailedExport: DocumentPlace {
    func write(_ bytes: Secret) -> Bool {
        false
    }

    func readBack(limit: Int) -> Secret? {
        nil
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

    /// Called on the model's worker: one read (readAtMost).
    func read(limit: Int) -> Secret? {
        readAtMost(url, limit: limit)
    }
}

/// One read of the file at url of at most limit + 1 bytes, inside its security scope, through a handle that
/// closes as it goes, the bytes copied once into a Secret and the Data they came in wiped; nil when it
/// cannot be opened.
private func readAtMost(_ url: URL, limit: Int) -> Secret? {
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
