// Reading the picked .age backup is a local file read (rule 8), not a fetch.
let sealed = try Data(contentsOf: backupURL)
let again = try Data(contentsOf: url)
// A file the picker hands back, by path or as a URL, is a local read too.
let picked = try Data(contentsOf: URL(fileURLWithPath: path))
let chosen = try Data(contentsOf: pickedURL)
let snapshot = try Data(contentsOf: URL(filePath: kcrPath))
// A URL built from a string that is no literal, and never fetched, passes Network.
let settings = URL(string: localName)
