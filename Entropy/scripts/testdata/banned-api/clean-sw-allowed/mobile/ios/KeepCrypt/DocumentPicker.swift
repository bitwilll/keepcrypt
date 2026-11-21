import SwiftUI
import UniformTypeIdentifiers

// The backup handed to the system's picker in memory, and the picked file read back.
struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let sealed: Data

    init(sealed: Data) {
        self.sealed = sealed
    }

    init(configuration: ReadConfiguration) throws {
        guard let bytes = configuration.file.regularFileContents else { throw CocoaError(.fileReadCorruptFile) }
        sealed = bytes
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: sealed)
    }
}

struct BackupButton: View {
    @State private var saving = false
    let backup: BackupDocument

    var body: some View {
        Button("Save backup") { saving = true }
            .fileExporter(isPresented: $saving, document: backup, contentType: .data) { result in }
    }
}

func readBack(_ url: URL) throws -> Data {
    try Data(contentsOf: url)
}
