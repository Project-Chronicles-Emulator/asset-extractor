<h1 align="center">Project Chronicles · Asset Extractor</h1>

<p align="center">Extract a private snapshot, recover descriptors and build your own static catalog.</p>

<p align="center"><a href="https://github.com/Project-Chronicles-Emulator/game-server">Project home</a> · <a href="https://github.com/Project-Chronicles-Emulator/sdk-generator">SDK generator</a> · <a href="https://github.com/Project-Chronicles-Emulator/game-server/blob/main/docs/guides/game-data.md">Runtime data guide</a></p>

Standalone source for the researched Chronicles archive reader, descriptor/catalog
builders and native packet-log utilities. Archive reading uses pinned public
[CUE4Parse source](https://github.com/FabianFG/CUE4Parse/tree/28f385e622468c4ab84997d596b46bb1c3adfcfa);
Python handles descriptor recovery, catalogs and verification.

**No game files are included:** no client archives/binaries, extracted assets,
descriptor/opcode exports, SDK dumps, captured packets or decoder DLLs.
The validated archive key for the October 23, 2026 demo is documented below.
Supply your own compatible local inputs. Synthetic decoder tests create their own
small schemas in a temporary directory.

## Build

Requires Git, PowerShell 7.2+, .NET 10 SDK and Python:

```powershell
python -m pip install -r requirements.txt
pwsh -File build.ps1
```

The script fetches the researched CUE4Parse revision into ignored `out/dependencies`
and applies the checked-in transitive dependency version configuration during build.
It refuses an existing dependency checkout at a different commit. No private sibling
project or copied dependency binaries are needed. Upstream dependencies retain their
own licenses/notices.

Output: `bin/Release/net10.0/ChroniclesAssetExtractor.dll`.

## 1. Extract your local archives

Run from the repository root. Use a new output directory outside the installed client:

```powershell
$paks = 'D:\Games\Chronicles\X5\Content\Paks'
$snapshot = Join-Path (Get-Location) 'out/client-extraction'
$archiveKey = Join-Path (Get-Location) 'out/archive-key.local.txt'
$oodle = 'D:\LocalTools\oo2core_9_win64.dll'

Set-Content -LiteralPath $archiveKey -NoNewline `
    -Value '399E5CE7FC1100522BD20D7F7C9A86AA946A9BE0610EF10EF5136A04799224B1'

dotnet bin/Release/net10.0/ChroniclesAssetExtractor.dll `
    $paks $snapshot --extract --key $archiveKey --oodle $oodle
```

The 64-character hexadecimal key above was validated against the installed
October 23, 2026 demo archives. Other client builds may use a different key.
Keep the key file outside the extraction output: that directory must be empty
when the reader starts. The reader uses the supplied key and decoder; it reads
archives, normalizes the researched custom metadata in memory and records file
sizes/hashes.
Source archives remain unchanged. Existing populated output directories are refused.
Check the exit status and failed-file count before continuing.

For a small reader check, append `--extract-prefix X5/Content/Design/CMS/`. A CMS-only
snapshot is not a full input for map/placement/tutorial generators.

## 2. Recover descriptors and build catalogs

```powershell
$matchingDump = 'D:\PrivateResearch\ArcheAgeChronicles.memdump.exe'
python extract_protobuf.py $matchingDump "$snapshot/Protocol"
python build_catalog.py $snapshot
python verify_extraction.py $snapshot
```

Use a matching descriptor-bearing executable/memory dump. A protected or different
on-disk executable may not expose those descriptors. The tooling produces local
`Protocol/`, `Catalog/`, raw files and provenance manifests; none are committed here.

The archive reader and consuming profile generators target a researched demo build,
not all future clients. Keep new builds separate and review their hashes/layouts.
Decoded metadata does not establish transport or gameplay compatibility.

## 3. Export data for the emulator

From a separate **game-server** checkout, point its runtime exporter at this verified
snapshot:

```powershell
python tools/export_client_data.py --source D:/YourSnapshot --include-raw
python tools/export_client_data.py --verify-only
```

Follow [the full runtime data guide](https://github.com/Project-Chronicles-Emulator/game-server/blob/main/docs/guides/game-data.md)
for profile generation and loader prerequisites. This extractor can be built and
used independently of the game server.

## Optional packet tooling

`extract_opcodes.py`, `capture_packets.py` and `decode_packets.py` operate on local
matching inputs. Use `--help` for their arguments. The capture helper reads an existing
native log into a new capture directory; it does not enable logging or inject code.
Keep packet logs private: they can contain account/session/player values.

```powershell
python -m unittest test_packet_decoder -v
```

The four synthetic checks validate framing, sequence/payload separation and schema
lookup. They require no client, recovered descriptor file or archive key.

## Contribute

Preserve read-only source access, fresh-output protection, build identity and manifest
verification. Keep all game-derived files and credentials local. Include a reproducible
sanitized failure and distinguish synthetic/static extraction checks from gameplay.

The standalone project was compiled separately and its synthetic decoder tests passed.
Static extraction checks establish only the tested data path, not original-client gameplay.

## Preview downloads and reproducible releases

The **Actions → Release preview** workflow builds a Windows x64 package from a
clean checkout and creates a draft prerelease with its SHA-256 checksum. Choose a
new `vMAJOR.MINOR.PATCH-preview.NUMBER` tag when dispatching it. A failed build does
not create a release. Published previews appear on this repository's Releases page.

Packages contain the application and selected support files only. The included
README documents the demo archive key; no key file, client installation,
extracted game data or credentials are packaged. Keep the whole package together;
follow the setup instructions above before starting it. Windows
C++ applications require the Microsoft Visual C++ x64 runtime; desktop interfaces
also require Microsoft Edge WebView2 Runtime. The extractor package requires .NET 10.
These experimental previews do not establish compatibility with another client build.
