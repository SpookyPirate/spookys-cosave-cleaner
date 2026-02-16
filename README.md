# Spooky's CoSave Cleaner

A GUI tool for inspecting and surgically cleaning SKSE co-save (`.skse`) files used by Skyrim Special Edition and Skyrim VR. Built with Python and tkinter — no external dependencies.

## What It Does

SKSE (Skyrim Script Extender) stores plugin data in `.skse` co-save files alongside each game save (`.ess`). Over time, these files can accumulate orphaned or bloated data from removed or malfunctioning mods — sometimes growing to hundreds of megabytes or even gigabytes. This causes long load times, memory exhaustion, and crashes.

Spooky's CoSave Cleaner lets you:

- **Browse** the internal structure of any `.skse` file
- **Inspect** individual plugins and data chunks with full metadata and hex previews
- **Identify bloat** — oversized chunks are highlighted automatically
- **Selectively remove** entire chunks or individual entries within PapyrusUtil STRL chunks
- **Edit STRL data** — surgically remove specific StorageUtil string list entries while preserving others
- **Rebuild** the file with integrity verification before saving

## Installation

### Standalone Executable

Download `Spookys_CoSave_Cleaner.exe` — no Python installation needed. Just run it.

### From Source

Requires Python 3.8+ with tkinter (included in standard Python installations). No third-party packages.

```
python skse_cosave_cleaner.py
```

### Building the Executable

```
pip install pyinstaller
pyinstaller --onefile --windowed --name "Spookys_CoSave_Cleaner" skse_cosave_cleaner.py
```

## Usage

### Opening a File

Click **Open File...** and select an `.skse` co-save file. These are located alongside your `.ess` save files, typically in:

- **Skyrim SE**: `%USERPROFILE%\Documents\My Games\Skyrim Special Edition\Saves\`
- **Skyrim VR**: `%USERPROFILE%\Documents\My Games\Skyrim VR\Saves\`
- **MO2 users**: Inside your MO2 profile's `saves/` folder

The header bar shows the file's format version, SKSE version, runtime version, and plugin count.

### Browsing the Structure

The left panel shows a tree of all plugins and their chunks:

- **Plugins** are top-level nodes showing the plugin name (or FourCC UID), hex UID, and total data size
- **Chunks** are nested under each plugin, showing the FourCC type and size
- Click a plugin or chunk to view its details in the right panel

#### Color Coding

| Color | Meaning |
|-------|---------|
| White | Plugin header |
| Gray | Normal chunk (< 1 MB) |
| Orange | Warning — chunk is 1–10 MB |
| Red | Bloat — chunk is > 10 MB (with `!!!` marker and % of file) |

### Sorting

Click any column header to sort:

- **Plugin / Chunk** — alphabetical by name
- **Size** — by data size (defaults to largest-first)
- **Del?** — by checked state (checked items first)

Click the same header again to reverse the sort direction. An arrow (▲/▼) indicates the active sort.

### Inspecting Details

Click any plugin or chunk in the tree to see full details in the right panel:

**Plugin details** include: UID (hex + ASCII), chunk count, data size, percentage of file, file offset, and a summary of all chunks.

**Chunk details** include: FourCC type, description (for known types), version, data size, total size with header, percentage of plugin and file, file offset, removal status, parent plugin, and a hex dump of the first 256 bytes.

### Selecting Chunks for Removal

- Click the **Del?** column on a chunk row to toggle its checkbox
- Click **Del?** on a plugin row to toggle all chunks under that plugin
- Use the **Select All Chunks** checkbox to toggle everything
- The bottom bar shows a running count and total size of selected chunks

### Editing STRL Entries (PapyrusUtil String Lists)

When you select a PapyrusUtil STRL chunk, an **Edit STRL Entries...** button appears below the details panel. This opens a dedicated editor that:

1. Parses the STRL chunk's internal structure (objects, keys, and item counts)
2. Displays each entry with its form ID, key name, item count, and size
3. Lets you select individual entries for removal while preserving others
4. Rebuilds the STRL data with only the selected entries removed

This is useful when a STRL chunk contains a mix of legitimate mod data and bloated/orphaned entries — you can remove the bad data without losing the good.

### Cleaning and Saving

1. Select the chunks you want to remove (or use the STRL editor for finer control)
2. Click **Clean Selected**
3. Review the confirmation dialog listing all chunks to be removed
4. Click **Yes** to proceed
5. The tool rebuilds the file, verifies the output parses correctly, then prompts **Save As...**
6. The default output filename appends `_cleaned` before the extension

The original file is never modified.

## SKSE Co-Save Format

The `.skse` binary format is straightforward and documented in the SKSE source code:

```
File Header (20 bytes)
├── Magic: 'SKSE' (4 bytes)
├── Format Version (uint32)
├── SKSE Version (uint32, packed: major.minor.patch.build)
├── Runtime Version (uint32, packed)
└── Number of Plugins (uint32)

Per Plugin
├── Plugin Header (12 bytes)
│   ├── Plugin UID (uint32, typically a FourCC like 'JSTR')
│   ├── Number of Chunks (uint32)
│   └── Data Length (uint32, total bytes of all chunks below)
│
└── Per Chunk
    ├── Chunk Header (12 bytes)
    │   ├── Chunk Type (uint32, FourCC like 'STRL')
    │   ├── Version (uint32)
    │   └── Data Length (uint32)
    └── Chunk Data (variable length byte array)
```

All integer fields are little-endian. FourCC codes are stored as uint32 multi-character constants (e.g., `'JSTR'` in C++ becomes `0x4A535452`).

## Known Plugin UIDs

The tool maps common SKSE plugin UIDs to friendly names:

| UID | Name |
|-----|------|
| `0x00000000` | SKSE Core |
| `0x4A535452` | JContainers |
| `0x534B4545` | SKEE (RaceMenu) |
| `0x424510A2` | PapyrusUtil |
| `0x54534F00` | OStim |

Unknown UIDs display as their FourCC ASCII representation or hex value.

## Known Chunk Types

Common PapyrusUtil/StorageUtil chunk types:

| FourCC | Description |
|--------|-------------|
| `MODS` | Mod list / form mapping |
| `INTV` | Integer values |
| `FLTV` | Float values |
| `STRV` | String values |
| `FORV` | Form values |
| `INTL` | Integer lists |
| `FLTL` | Float lists |
| `STRL` | String lists |
| `FORL` | Form lists |
| `PLGN` | Plugin data |
| `LMOD` | Light mod data |

## Architecture

- **Zero dependencies**: Only Python stdlib (`tkinter`, `struct`, `os`, `ctypes`)
- **Single file**: No package structure, no build step, no config files
- **Lossless rebuild**: Raw bytes preserved, only headers recalculated
- **Non-destructive**: Original file is never modified; always Save As
- **Dark theme**: Full ttk style override with VS Code-inspired colors and Windows 11 dark title bar via DWM API

## License

MIT

## Credits

Parser logic based on the SKSE64/SKSEVR source code's co-save format documentation.
