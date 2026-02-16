"""
SKSE Co-Save Cleaner GUI
A general-purpose GUI tool for inspecting and cleaning SKSE co-save files.
Browse the plugin/chunk hierarchy, view details, and selectively remove chunks.

Dependencies: Python stdlib only (tkinter, struct, os)
"""

import struct
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ─── Dark Theme Colors ────────────────────────────────────────────────────────
BG           = "#1e1e1e"
BG_SECONDARY = "#252526"
BG_INPUT     = "#2d2d2d"
FG           = "#d4d4d4"
FG_DIM       = "#808080"
FG_HEADER    = "#ffffff"
ACCENT       = "#0078d4"
DANGER       = "#e74c3c"
WARNING      = "#e67e22"
SUCCESS      = "#27ae60"
SELECTION    = "#094771"
BORDER       = "#3c3c3c"
HOVER        = "#2a2d2e"

# ─── Known Plugin UIDs ────────────────────────────────────────────────────────
KNOWN_PLUGINS = {
    # UIDs are multi-char constants from SKSE serialization registration
    # Displayed as big-endian FourCC (matching how devs write them in C++)
    0x00000000: "SKSE Core",
    0x00000001: "SKSE Core (1)",
    0x42424C54: "TLBB",
    0x504F5244: "DROP",
    0x4D534944: "DISM",
    0x4E594453: "SDYN",
    0x45585045: "EXPE",
    0x4A535452: "JContainers",
    0x4C4C4752: "LLGR",
    0x44474E00: "DGN",
    0x4F49464C: "OIFL",
    0x54534F00: "OStim",
    0x53544656: "STFV",
    0x4645434B: "FECK",
    0x50335045: "P3PE",
    0x00454346: "FCE",
    0x4E414C53: "NALS",
    0x534B4545: "SKEE (RaceMenu)",
    0x5354594C: "STYL",
    0x53504E53: "SPNS",
    0x424510A2: "PapyrusUtil",
    0xA0B0D9EE: "Unknown (A0B0D9EE)",
    0x4E494F56: "NiOverride",
}

# ─── Known Chunk FourCC Descriptions ──────────────────────────────────────────
CHUNK_DESCRIPTIONS = {
    "PLGN": "Plugin data",
    "LMOD": "Light mod data",
    "MODS": "Mod list / form mapping",
    "INTV": "Integer values (StorageUtil)",
    "FLTV": "Float values (StorageUtil)",
    "STRV": "String values (StorageUtil)",
    "FORV": "Form values (StorageUtil)",
    "INTL": "Integer lists (StorageUtil)",
    "FLTL": "Float lists (StorageUtil)",
    "STRL": "String lists (StorageUtil)",
    "FORL": "Form lists (StorageUtil)",
    "DATA": "Generic data",
    "GLOB": "Global data",
    "RACI": "Race info",
    "ACTI": "Activation data",
    "SLOT": "Slot data",
    "MODL": "Model data",
    "STAT": "Statistics",
    "MGEF": "Magic effect data",
}


# ─── Co-Save Parser (from clean_skse_cosave.py) ──────────────────────────────

def read_uint32(data, offset):
    return struct.unpack('<I', data[offset:offset + 4])[0]


def pack_uint32(value):
    return struct.pack('<I', value)


def fourcc_str(type_val):
    """Convert a uint32 chunk type to readable FourCC string."""
    b = struct.pack('<I', type_val)
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in reversed(b))


def uid_str(uid):
    """Convert a plugin UID to a readable FourCC string (big-endian, matching fourcc_str)."""
    b = struct.pack('<I', uid)
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in reversed(b))


def friendly_plugin_name(uid):
    """Return a friendly name for known plugin UIDs, or the raw UID string."""
    if uid in KNOWN_PLUGINS:
        return KNOWN_PLUGINS[uid]
    s = uid_str(uid)
    if all(c == '.' for c in s):
        return f"0x{uid:08X}"
    return s


def format_version(ver):
    """Format a packed version number like 0x01040F00 -> 1.4.15.0"""
    major = (ver >> 24) & 0xFF
    minor = (ver >> 16) & 0xFF
    patch = (ver >> 8) & 0xFF
    build = ver & 0xFF
    if build == 0:
        return f"{major}.{minor}.{patch}"
    return f"{major}.{minor}.{patch}.{build}"


def format_size(size):
    """Format byte size to human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def parse_cosave(data):
    """Parse the .skse co-save and return structured data."""
    if len(data) < 20:
        raise ValueError("File too small for SKSE header")

    magic = data[0:4]
    if magic != b'SKSE':
        raise ValueError(f"Invalid magic: {magic!r} (expected b'SKSE')")

    header = {
        'format_version': read_uint32(data, 4),
        'skse_version': read_uint32(data, 8),
        'runtime_version': read_uint32(data, 12),
        'num_plugins': read_uint32(data, 16),
    }

    plugins = []
    offset = 20

    for pi in range(header['num_plugins']):
        if offset + 12 > len(data):
            raise ValueError(f"Truncated plugin header {pi} at offset {offset}")

        plugin_uid = read_uint32(data, offset)
        num_chunks = read_uint32(data, offset + 4)
        plugin_len = read_uint32(data, offset + 8)

        plugin_data_start = offset + 12
        plugin_data_end = offset + 12 + plugin_len

        if plugin_data_end > len(data):
            raise ValueError(
                f"Plugin {pi} data extends past EOF: {plugin_data_end} > {len(data)}")

        chunks = []
        chunk_offset = plugin_data_start
        for ci in range(num_chunks):
            if chunk_offset + 12 > plugin_data_end:
                raise ValueError(
                    f"Truncated chunk {ci} in plugin {pi} at offset {chunk_offset}")

            chunk_type = read_uint32(data, chunk_offset)
            chunk_ver = read_uint32(data, chunk_offset + 4)
            chunk_len = read_uint32(data, chunk_offset + 8)

            chunk_data_start = chunk_offset + 12
            chunk_data_end = chunk_offset + 12 + chunk_len

            if chunk_data_end > plugin_data_end:
                raise ValueError(
                    f"Chunk {ci} in plugin {pi} extends past plugin boundary")

            chunks.append({
                'type': chunk_type,
                'version': chunk_ver,
                'length': chunk_len,
                'header_offset': chunk_offset,
                'data_offset': chunk_data_start,
                'data_end': chunk_data_end,
                'raw_header': data[chunk_offset:chunk_offset + 12],
                'raw_data': data[chunk_data_start:chunk_data_end],
            })

            chunk_offset += 12 + chunk_len

        plugins.append({
            'uid': plugin_uid,
            'num_chunks': num_chunks,
            'length': plugin_len,
            'header_offset': offset,
            'data_start': plugin_data_start,
            'data_end': plugin_data_end,
            'chunks': chunks,
        })

        offset = plugin_data_end

    return header, plugins


def rebuild_cosave(data, header, plugins, remove_set):
    """
    Rebuild the co-save, removing specified chunks.
    remove_set: set of (plugin_index, chunk_index) tuples to remove.
    Returns (cleaned_bytes, removed_info_list, total_removed_bytes).
    """
    out = bytearray()
    out.extend(data[0:20])  # header

    removed_chunks = []
    total_removed_bytes = 0

    for pi, plugin in enumerate(plugins):
        kept_chunks = []
        for ci, chunk in enumerate(plugin['chunks']):
            if (pi, ci) in remove_set:
                removed_chunks.append({
                    'plugin_index': pi,
                    'plugin_uid': plugin['uid'],
                    'chunk_type': fourcc_str(chunk['type']),
                    'chunk_length': chunk['length'],
                })
                total_removed_bytes += 12 + chunk['length']
            else:
                kept_chunks.append(chunk)

        new_plugin_len = sum(12 + ch['length'] for ch in kept_chunks)

        out.extend(pack_uint32(plugin['uid']))
        out.extend(pack_uint32(len(kept_chunks)))
        out.extend(pack_uint32(new_plugin_len))

        for chunk in kept_chunks:
            out.extend(chunk['raw_header'])
            out.extend(chunk['raw_data'])

    return bytes(out), removed_chunks, total_removed_bytes


# ─── STRL Data Parser/Rebuilder ──────────────────────────────────────────────

def _skip_n_tokens(data, start, n):
    """Skip n space-delimited tokens in byte data efficiently.
    Returns position after the nth token's trailing space."""
    if n <= 0:
        return start
    pos = start
    remaining = n
    CHUNK = 4 * 1024 * 1024  # 4MB

    while remaining > 0 and pos < len(data):
        chunk_end = min(pos + CHUNK, len(data))
        spaces = data.count(b' ', pos, chunk_end)

        if spaces >= remaining:
            # Narrow down with binary search, then linear scan
            lo, hi = pos, chunk_end
            while remaining > 500 and hi - lo > 4096:
                mid = (lo + hi) // 2
                spaces_lo = data.count(b' ', lo, mid)
                if spaces_lo >= remaining:
                    hi = mid
                else:
                    remaining -= spaces_lo
                    lo = mid
            p = lo
            for _ in range(remaining):
                sp = data.index(b' ', p)
                p = sp + 1
            return p

        remaining -= spaces
        pos = chunk_end

    return min(pos, len(data))


def parse_strl_structure(raw_data):
    """Parse STRL chunk data structure without materializing individual items.
    Returns list of entry dicts with byte offset info for efficient reconstruction.

    STRL format: objCount [objKey keyCount [keyName listSize [items...]]*]*
    Space-delimited. 0x1B = empty string, 0x07 = space within string.
    """
    pos = 0

    def read_token():
        nonlocal pos
        sp = raw_data.find(b' ', pos)
        if sp == -1:
            token = raw_data[pos:]
            pos = len(raw_data)
            return token
        token = raw_data[pos:sp]
        pos = sp + 1
        return token

    def decode_str(token):
        if token == b'\x1b':
            return ''
        return token.decode('ascii', errors='replace').replace('\x07', ' ')

    obj_count_token = read_token()
    try:
        obj_count = int(obj_count_token)
    except ValueError:
        raise ValueError(f"Invalid STRL obj_count: {obj_count_token!r}")

    entries = []
    for oi in range(obj_count):
        if pos >= len(raw_data):
            break  # data ended early

        obj_key_token = read_token()
        if not obj_key_token:
            break  # trailing space at end of data

        obj_key = 0 if obj_key_token == b'\x1b' else int(obj_key_token)

        key_count_token = read_token()
        if not key_count_token:
            break
        key_count = int(key_count_token)

        keys = []
        for ki in range(key_count):
            if pos >= len(raw_data):
                break

            key_start = pos
            key_name_token = read_token()
            key_name = decode_str(key_name_token)

            list_size_token = read_token()
            if not list_size_token:
                break
            list_size = int(list_size_token)

            if list_size > 0:
                pos = _skip_n_tokens(raw_data, pos, list_size)

            keys.append({
                'name': key_name,
                'list_size': list_size,
                'byte_range': (key_start, pos),
                'byte_size': pos - key_start,
            })

        entries.append({
            'obj_key': obj_key,
            'obj_key_token': obj_key_token,
            'keys': keys,
        })

    return entries


def rebuild_strl_data(raw_data, entries, remove_set):
    """Rebuild STRL data, removing entries in remove_set.
    remove_set: set of (obj_idx, key_idx) tuples to remove."""
    parts = []

    kept_objects = []
    for oi, entry in enumerate(entries):
        kept_keys = [key for ki, key in enumerate(entry['keys'])
                     if (oi, ki) not in remove_set]
        if kept_keys:
            kept_objects.append((entry, kept_keys))

    parts.append(str(len(kept_objects)).encode('ascii'))
    parts.append(b' ')

    for entry, kept_keys in kept_objects:
        parts.append(entry['obj_key_token'])
        parts.append(b' ')
        parts.append(str(len(kept_keys)).encode('ascii'))
        parts.append(b' ')

        for key in kept_keys:
            start, end = key['byte_range']
            parts.append(raw_data[start:end])

    return b''.join(parts)


# ─── GUI Application ─────────────────────────────────────────────────────────

class CosaveCleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Spooky's CoSave Cleaner")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        # State
        self.file_path = None
        self.raw_data = None
        self.header = None
        self.plugins = None
        self.checked = {}  # (plugin_idx, chunk_idx) -> BooleanVar
        self.sort_col = None   # current sort column
        self.sort_asc = True   # ascending or descending

        self._apply_dark_theme()
        self._build_ui()
        self._set_status("Ready — open an .skse file to begin")

    # ── Dark Theme ────────────────────────────────────────────────────────

    def _apply_dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_INPUT,
                         bordercolor=BORDER, darkcolor=BG, lightcolor=BG,
                         troughcolor=BG_SECONDARY, selectbackground=SELECTION,
                         selectforeground=FG_HEADER, font=("Segoe UI", 9))

        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TLabelframe", background=BG, foreground=FG)
        style.configure("TLabelframe.Label", background=BG, foreground=FG_HEADER,
                         font=("Segoe UI", 9, "bold"))

        style.configure("Header.TLabel", foreground=FG_HEADER,
                         font=("Segoe UI", 10, "bold"))
        style.configure("Dim.TLabel", foreground=FG_DIM)
        style.configure("Danger.TLabel", foreground=DANGER)
        style.configure("Path.TLabel", foreground=ACCENT)

        style.configure("TButton", background=BG_SECONDARY, foreground=FG,
                         bordercolor=BORDER, padding=(12, 4),
                         font=("Segoe UI", 9))
        style.map("TButton",
                   background=[("active", HOVER), ("pressed", ACCENT)],
                   foreground=[("active", FG_HEADER)])

        style.configure("Accent.TButton", background=ACCENT, foreground=FG_HEADER,
                         bordercolor=ACCENT, padding=(14, 5),
                         font=("Segoe UI", 9, "bold"))
        style.map("Accent.TButton",
                   background=[("active", "#1a8ad4"), ("pressed", "#005a9e")])

        style.configure("Danger.TButton", background=DANGER, foreground=FG_HEADER,
                         bordercolor=DANGER, padding=(14, 5),
                         font=("Segoe UI", 9, "bold"))
        style.map("Danger.TButton",
                   background=[("active", "#c0392b"), ("pressed", "#a93226")])

        style.configure("Treeview", background=BG_SECONDARY, foreground=FG,
                         fieldbackground=BG_SECONDARY, rowheight=22,
                         font=("Consolas", 9))
        style.configure("Treeview.Heading", background=BG, foreground=FG_HEADER,
                         font=("Segoe UI", 9, "bold"))
        style.map("Treeview",
                   background=[("selected", SELECTION)],
                   foreground=[("selected", FG_HEADER)])

        style.configure("TCheckbutton", background=BG, foreground=FG)
        style.map("TCheckbutton",
                   background=[("active", BG)],
                   foreground=[("active", FG_HEADER)])

        style.configure("Vertical.TScrollbar", background=BG_SECONDARY,
                         troughcolor=BG, bordercolor=BG, arrowcolor=FG_DIM)
        style.map("Vertical.TScrollbar",
                   background=[("active", HOVER)])

        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG,
                         insertcolor=FG)

        style.configure("TSeparator", background=BORDER)

    # ── UI Construction ───────────────────────────────────────────────────

    def _build_ui(self):
        # Top toolbar
        toolbar = ttk.Frame(self.root, padding=(8, 6))
        toolbar.pack(fill=tk.X)

        self.btn_open = ttk.Button(toolbar, text="Open File...",
                                    command=self._open_file)
        self.btn_open.pack(side=tk.LEFT)

        self.lbl_path = ttk.Label(toolbar, text="No file loaded",
                                   style="Path.TLabel", wraplength=500)
        self.lbl_path.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        self.lbl_size = ttk.Label(toolbar, text="", style="Dim.TLabel")
        self.lbl_size.pack(side=tk.RIGHT, padx=(10, 0))

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Header info bar
        self.header_frame = ttk.Frame(self.root, padding=(8, 4))
        self.header_frame.pack(fill=tk.X)
        self.lbl_header_info = ttk.Label(self.header_frame, text="",
                                          style="Dim.TLabel")
        self.lbl_header_info.pack(side=tk.LEFT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Main content: tree + details paned
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Left: tree
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=3)

        self.tree = ttk.Treeview(tree_frame, columns=("size", "check"),
                                  selectmode="browse", show="tree headings")
        self.tree.heading("#0", text="Plugin / Chunk", anchor=tk.W,
                           command=lambda: self._sort_tree("name"))
        self.tree.heading("size", text="Size", anchor=tk.E,
                           command=lambda: self._sort_tree("size"))
        self.tree.heading("check", text="Del?", anchor=tk.CENTER,
                           command=lambda: self._sort_tree("check"))

        self.tree.column("#0", width=400, minwidth=200)
        self.tree.column("size", width=100, minwidth=70, anchor=tk.E)
        self.tree.column("check", width=50, minwidth=40, anchor=tk.CENTER)

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                     command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-1>", self._on_tree_click)

        # Tag configs for highlighting
        self.tree.tag_configure("bloat", foreground=DANGER)
        self.tree.tag_configure("warn", foreground=WARNING)
        self.tree.tag_configure("plugin", foreground=FG_HEADER)
        self.tree.tag_configure("normal", foreground=FG)
        self.tree.tag_configure("checked", foreground=DANGER)

        # Right: details panel
        detail_frame = ttk.Frame(paned, padding=(8, 4))
        paned.add(detail_frame, weight=2)

        ttk.Label(detail_frame, text="Details", style="Header.TLabel").pack(
            anchor=tk.W, pady=(0, 6))

        self.action_frame = ttk.Frame(detail_frame)
        self.action_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(6, 0))

        self.detail_text = tk.Text(detail_frame, wrap=tk.WORD, bg=BG_SECONDARY,
                                    fg=FG, font=("Consolas", 9),
                                    insertbackground=FG, relief=tk.FLAT,
                                    borderwidth=0, padx=8, pady=8,
                                    state=tk.DISABLED)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Text tags for detail panel
        self.detail_text.tag_configure("heading",
                                        foreground=FG_HEADER,
                                        font=("Segoe UI", 10, "bold"))
        self.detail_text.tag_configure("label",
                                        foreground=ACCENT,
                                        font=("Consolas", 9, "bold"))
        self.detail_text.tag_configure("value", foreground=FG)
        self.detail_text.tag_configure("danger", foreground=DANGER)
        self.detail_text.tag_configure("dim", foreground=FG_DIM)
        self.detail_text.tag_configure("hex",
                                        foreground="#9cdcfe",
                                        font=("Consolas", 9))

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Bottom bar
        bottom = ttk.Frame(self.root, padding=(8, 6))
        bottom.pack(fill=tk.X)

        self.select_all_var = tk.BooleanVar(value=False)
        self.chk_select_all = ttk.Checkbutton(
            bottom, text="Select All Chunks",
            variable=self.select_all_var, command=self._toggle_select_all)
        self.chk_select_all.pack(side=tk.LEFT)

        self.lbl_selection = ttk.Label(bottom, text="Selected: 0 chunks (0 B)",
                                        style="Dim.TLabel")
        self.lbl_selection.pack(side=tk.LEFT, padx=(16, 0))

        self.btn_exit = ttk.Button(bottom, text="Exit",
                                    command=self.root.quit)
        self.btn_exit.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_save = ttk.Button(bottom, text="Save As...",
                                    command=self._save_as, state=tk.DISABLED)
        self.btn_save.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_clean = ttk.Button(bottom, text="Clean Selected",
                                     style="Accent.TButton",
                                     command=self._clean_selected,
                                     state=tk.DISABLED)
        self.btn_clean.pack(side=tk.RIGHT, padx=(4, 0))

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Status bar
        status_frame = ttk.Frame(self.root, padding=(8, 3))
        status_frame.pack(fill=tk.X)
        self.lbl_status = ttk.Label(status_frame, text="", style="Dim.TLabel")
        self.lbl_status.pack(side=tk.LEFT)

    # ── File Operations ───────────────────────────────────────────────────

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open SKSE Co-Save",
            filetypes=[("SKSE Co-Saves", "*.skse"), ("All Files", "*.*")],
            initialdir=os.path.expanduser("~\\Desktop"))
        if not path:
            return
        self._load_file(path)

    def _load_file(self, path):
        self._set_status(f"Loading {os.path.basename(path)}...")
        self.root.update_idletasks()

        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{e}")
            self._set_status("Error loading file")
            return

        try:
            header, plugins = parse_cosave(data)
        except Exception as e:
            messagebox.showerror("Parse Error",
                                  f"Failed to parse co-save:\n{e}")
            self._set_status("Error parsing file")
            return

        self.file_path = path
        self.raw_data = data
        self.header = header
        self.plugins = plugins
        self.checked.clear()
        self.cleaned_data = None
        self.select_all_var.set(False)

        self.btn_save.configure(state=tk.DISABLED)

        self._update_header_display()
        self._populate_tree()
        self._update_selection_label()
        self._clear_details()
        self._set_status(f"Loaded: {os.path.basename(path)}")

    def _update_header_display(self):
        self.lbl_path.configure(text=self.file_path)
        self.lbl_size.configure(text=format_size(len(self.raw_data)))

        h = self.header
        skse_ver = format_version(h['skse_version'])
        rt_ver = format_version(h['runtime_version'])
        info = (f"Format: {h['format_version']}   |   "
                f"SKSE: {skse_ver}   |   "
                f"Runtime: {rt_ver}   |   "
                f"Plugins: {h['num_plugins']}")
        self.lbl_header_info.configure(text=info)

    # ── Tree Management ───────────────────────────────────────────────────

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.checked.clear()

        total_size = len(self.raw_data)
        SIZE_WARN = 1 * 1024 * 1024      # 1 MB
        SIZE_BLOAT = 10 * 1024 * 1024     # 10 MB

        for pi, plugin in enumerate(self.plugins):
            name = friendly_plugin_name(plugin['uid'])
            uid_hex = f"0x{plugin['uid']:08X}"
            plugin_label = f"Plugin {pi}: {name}"
            if name != uid_hex:
                plugin_label += f"  [{uid_hex}]"

            plugin_id = self.tree.insert(
                "", tk.END, iid=f"p{pi}",
                text=plugin_label,
                values=(format_size(plugin['length']), ""),
                tags=("plugin",),
                open=False)

            for ci, chunk in enumerate(plugin['chunks']):
                cc = fourcc_str(chunk['type'])
                chunk_size = chunk['length']
                total_chunk = 12 + chunk_size  # header + data

                # Determine tags
                tags = []
                if chunk_size >= SIZE_BLOAT:
                    tags.append("bloat")
                elif chunk_size >= SIZE_WARN:
                    tags.append("warn")
                else:
                    tags.append("normal")

                # Size annotation
                size_str = format_size(total_chunk)

                # Bloat marker
                label = cc
                if chunk_size >= SIZE_BLOAT:
                    pct = (total_chunk / total_size * 100) if total_size > 0 else 0
                    label += f"  !!!  ({pct:.1f}% of file)"

                var = tk.BooleanVar(value=False)
                self.checked[(pi, ci)] = var

                self.tree.insert(
                    plugin_id, tk.END, iid=f"c{pi}_{ci}",
                    text=f"    {label}",
                    values=(size_str, "\u2610"),  # ☐
                    tags=tuple(tags))

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        self._show_details(item_id)

    def _on_tree_click(self, event):
        """Handle clicks on the check column to toggle chunk selection."""
        region = self.tree.identify_region(event.x, event.y)
        col = self.tree.identify_column(event.x)
        item_id = self.tree.identify_row(event.y)

        if not item_id:
            return

        # Click on check column (#2) or on the tree text area for chunks
        if col == "#2" and item_id.startswith("c"):
            self._toggle_chunk(item_id)
        elif col == "#2" and item_id.startswith("p"):
            self._toggle_plugin(item_id)

    def _toggle_chunk(self, item_id):
        """Toggle a single chunk's checked state."""
        parts = item_id[1:].split("_")
        pi, ci = int(parts[0]), int(parts[1])
        key = (pi, ci)

        if key not in self.checked:
            return

        var = self.checked[key]
        var.set(not var.get())
        self._update_check_display(item_id, var.get())
        self._update_selection_label()
        self._update_clean_button()
        self._refresh_details_if_selected(item_id)

    def _toggle_plugin(self, item_id):
        """Toggle all chunks under a plugin."""
        pi = int(item_id[1:])
        children = self.tree.get_children(item_id)

        # Determine target state: if any unchecked, check all; else uncheck all
        any_unchecked = False
        for child in children:
            parts = child[1:].split("_")
            key = (int(parts[0]), int(parts[1]))
            if key in self.checked and not self.checked[key].get():
                any_unchecked = True
                break

        target = any_unchecked
        for child in children:
            parts = child[1:].split("_")
            key = (int(parts[0]), int(parts[1]))
            if key in self.checked:
                self.checked[key].set(target)
                self._update_check_display(child, target)

        self._update_selection_label()
        self._update_clean_button()

    def _update_check_display(self, item_id, is_checked):
        """Update the check column display and tags for a chunk."""
        symbol = "\u2611" if is_checked else "\u2610"  # ☑ / ☐
        current_vals = self.tree.item(item_id, "values")
        self.tree.item(item_id, values=(current_vals[0], symbol))

        # Update tags for visual feedback
        parts = item_id[1:].split("_")
        pi, ci = int(parts[0]), int(parts[1])
        chunk = self.plugins[pi]['chunks'][ci]
        chunk_size = chunk['length']

        SIZE_WARN = 1 * 1024 * 1024
        SIZE_BLOAT = 10 * 1024 * 1024

        if is_checked:
            tags = ("checked",)
        elif chunk_size >= SIZE_BLOAT:
            tags = ("bloat",)
        elif chunk_size >= SIZE_WARN:
            tags = ("warn",)
        else:
            tags = ("normal",)

        self.tree.item(item_id, tags=tags)

    def _toggle_select_all(self):
        target = self.select_all_var.get()
        for (pi, ci), var in self.checked.items():
            var.set(target)
            self._update_check_display(f"c{pi}_{ci}", target)
        self._update_selection_label()
        self._update_clean_button()

    def _update_selection_label(self):
        count = 0
        total_bytes = 0
        for (pi, ci), var in self.checked.items():
            if var.get():
                chunk = self.plugins[pi]['chunks'][ci]
                count += 1
                total_bytes += 12 + chunk['length']
        self.lbl_selection.configure(
            text=f"Selected: {count} chunk{'s' if count != 1 else ''} "
                 f"({format_size(total_bytes)})")

    def _update_clean_button(self):
        any_checked = any(v.get() for v in self.checked.values())
        self.btn_clean.configure(
            state=tk.NORMAL if any_checked else tk.DISABLED)

    # ── Sorting ───────────────────────────────────────────────────────────

    def _sort_tree(self, col):
        """Sort the tree by column. Toggles ascending/descending on repeat click."""
        if not self.plugins:
            return

        # Toggle direction if same column clicked again
        if self.sort_col == col:
            self.sort_asc = not self.sort_asc
        else:
            self.sort_col = col
            self.sort_asc = True  # size defaults descending on first click
            if col == "size":
                self.sort_asc = False

        # Update header arrows
        arrow = " \u25b2" if self.sort_asc else " \u25bc"
        self.tree.heading("#0", text="Plugin / Chunk" + (arrow if col == "name" else ""))
        self.tree.heading("size", text="Size" + (arrow if col == "size" else ""))
        self.tree.heading("check", text="Del?" + (arrow if col == "check" else ""))

        # Build sort keys for plugins
        plugin_items = self.tree.get_children("")
        plugin_keys = []
        for pid in plugin_items:
            pi = int(pid[1:])
            plugin = self.plugins[pi]

            if col == "name":
                key = friendly_plugin_name(plugin['uid']).lower()
            elif col == "size":
                key = plugin['length']
            elif col == "check":
                # Sort by count of checked chunks (more checked = first)
                count = sum(1 for ci in range(len(plugin['chunks']))
                            if self.checked.get((pi, ci), tk.BooleanVar()).get())
                key = count
            else:
                key = 0

            plugin_keys.append((key, pid))

        plugin_keys.sort(key=lambda x: x[0], reverse=not self.sort_asc)

        # Reorder plugins
        for idx, (_, pid) in enumerate(plugin_keys):
            self.tree.move(pid, "", idx)

        # Sort chunks within each plugin
        for pid in plugin_items:
            pi = int(pid[1:])
            chunk_items = self.tree.get_children(pid)
            chunk_keys = []
            for cid in chunk_items:
                parts = cid[1:].split("_")
                ci = int(parts[1])
                chunk = self.plugins[pi]['chunks'][ci]

                if col == "name":
                    key = fourcc_str(chunk['type']).lower()
                elif col == "size":
                    key = chunk['length']
                elif col == "check":
                    key = 1 if self.checked.get((pi, ci), tk.BooleanVar()).get() else 0
                else:
                    key = 0

                chunk_keys.append((key, cid))

            chunk_keys.sort(key=lambda x: x[0], reverse=not self.sort_asc)

            for idx, (_, cid) in enumerate(chunk_keys):
                self.tree.move(cid, pid, idx)

    # ── Details Panel ─────────────────────────────────────────────────────

    def _clear_details(self):
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "Select a plugin or chunk to view details.",
                                 "dim")
        self.detail_text.configure(state=tk.DISABLED)
        for w in self.action_frame.winfo_children():
            w.destroy()

    def _show_details(self, item_id):
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        for w in self.action_frame.winfo_children():
            w.destroy()

        if item_id.startswith("p"):
            self._show_plugin_details(int(item_id[1:]))
        elif item_id.startswith("c"):
            parts = item_id[1:].split("_")
            self._show_chunk_details(int(parts[0]), int(parts[1]))

        self.detail_text.configure(state=tk.DISABLED)

    def _show_plugin_details(self, pi):
        plugin = self.plugins[pi]
        t = self.detail_text

        name = friendly_plugin_name(plugin['uid'])
        t.insert(tk.END, f"Plugin {pi}: {name}\n", "heading")
        t.insert(tk.END, "\n")

        t.insert(tk.END, "UID:          ", "label")
        t.insert(tk.END, f"0x{plugin['uid']:08X}\n", "value")

        t.insert(tk.END, "UID (ASCII):  ", "label")
        t.insert(tk.END, f"{uid_str(plugin['uid'])}\n", "value")

        t.insert(tk.END, "Chunks:       ", "label")
        t.insert(tk.END, f"{plugin['num_chunks']}\n", "value")

        t.insert(tk.END, "Data size:    ", "label")
        t.insert(tk.END, f"{plugin['length']:,} bytes ({format_size(plugin['length'])})\n", "value")

        total = len(self.raw_data) if self.raw_data else 1
        pct = plugin['length'] / total * 100
        t.insert(tk.END, "% of file:    ", "label")
        tag = "danger" if pct > 50 else "value"
        t.insert(tk.END, f"{pct:.2f}%\n", tag)

        t.insert(tk.END, "Offset:       ", "label")
        t.insert(tk.END, f"0x{plugin['header_offset']:X}\n", "value")

        # Chunk summary
        t.insert(tk.END, "\nChunks:\n", "heading")
        for ci, chunk in enumerate(plugin['chunks']):
            cc = fourcc_str(chunk['type'])
            size = format_size(chunk['length'])
            desc = CHUNK_DESCRIPTIONS.get(cc, "")
            line = f"  {cc}  {size:>10}"
            if desc:
                line += f"  — {desc}"
            line += "\n"
            tag = "danger" if chunk['length'] >= 10 * 1024 * 1024 else "value"
            t.insert(tk.END, line, tag)

    def _show_chunk_details(self, pi, ci):
        plugin = self.plugins[pi]
        chunk = plugin['chunks'][ci]
        t = self.detail_text

        cc = fourcc_str(chunk['type'])
        desc = CHUNK_DESCRIPTIONS.get(cc, "Unknown")

        t.insert(tk.END, f"Chunk: {cc}\n", "heading")
        t.insert(tk.END, "\n")

        t.insert(tk.END, "Type:         ", "label")
        t.insert(tk.END, f"{cc} (0x{chunk['type']:08X})\n", "value")

        t.insert(tk.END, "Description:  ", "label")
        t.insert(tk.END, f"{desc}\n", "value")

        t.insert(tk.END, "Version:      ", "label")
        t.insert(tk.END, f"{chunk['version']}\n", "value")

        t.insert(tk.END, "Data size:    ", "label")
        t.insert(tk.END, f"{chunk['length']:,} bytes ({format_size(chunk['length'])})\n", "value")

        total_chunk = 12 + chunk['length']
        t.insert(tk.END, "Total size:   ", "label")
        t.insert(tk.END, f"{total_chunk:,} bytes (incl. 12-byte header)\n", "value")

        # % of plugin
        if plugin['length'] > 0:
            pct_plugin = total_chunk / (plugin['length'] + 12) * 100
            t.insert(tk.END, "% of plugin:  ", "label")
            tag = "danger" if pct_plugin > 80 else "value"
            t.insert(tk.END, f"{pct_plugin:.2f}%\n", tag)

        # % of file
        total_file = len(self.raw_data) if self.raw_data else 1
        pct_file = total_chunk / total_file * 100
        t.insert(tk.END, "% of file:    ", "label")
        tag = "danger" if pct_file > 50 else "value"
        t.insert(tk.END, f"{pct_file:.2f}%\n", tag)

        t.insert(tk.END, "Offset:       ", "label")
        t.insert(tk.END, f"0x{chunk['header_offset']:X}\n", "value")

        # Checked state
        key = (pi, ci)
        if key in self.checked:
            state = "MARKED FOR REMOVAL" if self.checked[key].get() else "Keeping"
            tag = "danger" if self.checked[key].get() else "value"
            t.insert(tk.END, "Status:       ", "label")
            t.insert(tk.END, f"{state}\n", tag)

        # Parent plugin
        plugin_name = friendly_plugin_name(plugin['uid'])
        t.insert(tk.END, "\nParent:       ", "label")
        t.insert(tk.END, f"Plugin {pi}: {plugin_name}\n", "value")

        # Hex preview
        t.insert(tk.END, "\n")
        t.insert(tk.END, "Hex Preview (first 256 bytes):\n", "heading")
        t.insert(tk.END, "\n")

        preview_len = min(256, chunk['length'])
        preview_data = chunk['raw_data'][:preview_len]
        self._insert_hex_dump(t, preview_data)

        if chunk['length'] > preview_len:
            t.insert(tk.END,
                      f"\n... {chunk['length'] - preview_len:,} more bytes ...\n",
                      "dim")

        # STRL entry editor for PapyrusUtil STRL chunks
        if cc == "STRL" and plugin['uid'] == 0x424510A2:
            btn = ttk.Button(self.action_frame, text="Edit STRL Entries...",
                              style="Accent.TButton",
                              command=lambda p=pi, c=ci: self._open_strl_editor(p, c))
            btn.pack(side=tk.LEFT)

    def _insert_hex_dump(self, text_widget, data):
        """Insert a formatted hex dump into the text widget."""
        for row_start in range(0, len(data), 16):
            row = data[row_start:row_start + 16]

            # Offset
            text_widget.insert(tk.END, f"  {row_start:08X}  ", "dim")

            # Hex bytes
            hex_parts = []
            for i, b in enumerate(row):
                hex_parts.append(f"{b:02X}")
                if i == 7:
                    hex_parts.append("")
            hex_str = " ".join(hex_parts)
            text_widget.insert(tk.END, f"{hex_str:<50}", "hex")

            # ASCII
            ascii_str = "".join(
                chr(b) if 32 <= b < 127 else "." for b in row)
            text_widget.insert(tk.END, f"  {ascii_str}\n", "dim")

    def _refresh_details_if_selected(self, item_id):
        sel = self.tree.selection()
        if sel and sel[0] == item_id:
            self._show_details(item_id)

    # ── STRL Entry Editor ─────────────────────────────────────────────────

    def _open_strl_editor(self, pi, ci):
        """Open the STRL entry editor dialog for a PapyrusUtil STRL chunk."""
        dialog = STRLEditorDialog(self, pi, ci)
        self.root.wait_window(dialog.dialog)

        if dialog.result is not None:
            old_len = self.plugins[pi]['chunks'][ci]['length']
            new_data = dialog.result
            new_len = len(new_data)

            # Update chunk in memory
            self.plugins[pi]['chunks'][ci]['raw_data'] = new_data
            self.plugins[pi]['chunks'][ci]['length'] = new_len
            self.plugins[pi]['chunks'][ci]['raw_header'] = (
                self.plugins[pi]['chunks'][ci]['raw_header'][:8] +
                pack_uint32(new_len))

            # Rebuild full co-save with modified chunk
            self._set_status("Rebuilding co-save with edited STRL data...")
            self.root.update_idletasks()

            try:
                cleaned, _, _ = rebuild_cosave(
                    self.raw_data, self.header, self.plugins, set())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to rebuild:\n{e}")
                self._set_status("Rebuild failed")
                return

            # Verify
            self._set_status("Verifying...")
            self.root.update_idletasks()

            try:
                h2, p2 = parse_cosave(cleaned)
                total_chunks = sum(p['num_chunks'] for p in p2)
            except Exception as e:
                messagebox.showerror("Verification Failed",
                    f"Modified file failed verification:\n{e}")
                self._set_status("Verification failed")
                return

            self.cleaned_data = cleaned
            self.btn_save.configure(state=tk.NORMAL)

            saved = old_len - new_len
            self._set_status(
                f"STRL edited: {format_size(saved)} reduced. "
                f"Verified: {h2['num_plugins']} plugins, {total_chunks} chunks.")

            self._save_as()

    # ── Clean / Save ──────────────────────────────────────────────────────

    def _clean_selected(self):
        remove_set = set()
        for (pi, ci), var in self.checked.items():
            if var.get():
                remove_set.add((pi, ci))

        if not remove_set:
            messagebox.showinfo("Nothing Selected",
                                 "No chunks are selected for removal.")
            return

        # Build summary
        total_bytes = sum(
            12 + self.plugins[pi]['chunks'][ci]['length']
            for pi, ci in remove_set)
        summary_lines = []
        for pi, ci in sorted(remove_set):
            plugin = self.plugins[pi]
            chunk = plugin['chunks'][ci]
            cc = fourcc_str(chunk['type'])
            pname = friendly_plugin_name(plugin['uid'])
            summary_lines.append(
                f"  Plugin {pi} ({pname}) -> {cc} ({format_size(chunk['length'])})")

        summary = "\n".join(summary_lines)
        msg = (f"Remove {len(remove_set)} chunk(s) totaling "
               f"{format_size(total_bytes)}?\n\n{summary}\n\n"
               f"Original file will NOT be modified.\n"
               f"You will be prompted to save the cleaned file.")

        if not messagebox.askyesno("Confirm Removal", msg):
            return

        self._set_status("Cleaning...")
        self.root.update_idletasks()

        try:
            cleaned, removed, total_removed = rebuild_cosave(
                self.raw_data, self.header, self.plugins, remove_set)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to rebuild co-save:\n{e}")
            self._set_status("Clean failed")
            return

        # Verify
        self._set_status("Verifying cleaned file...")
        self.root.update_idletasks()

        try:
            h2, p2 = parse_cosave(cleaned)
            total_chunks = sum(p['num_chunks'] for p in p2)
        except Exception as e:
            messagebox.showerror("Verification Failed",
                                  f"Cleaned file failed verification:\n{e}\n\n"
                                  f"The file will NOT be saved.")
            self._set_status("Verification failed — file not saved")
            return

        self.cleaned_data = cleaned
        self.btn_save.configure(state=tk.NORMAL)

        orig_size = len(self.raw_data)
        new_size = len(cleaned)
        reduction = orig_size - new_size

        self._set_status(
            f"Cleaned! {len(removed)} chunks removed "
            f"({format_size(reduction)} saved). "
            f"Verified: {h2['num_plugins']} plugins, {total_chunks} chunks. "
            f"Click 'Save As...' to write.")

        # Auto-prompt save
        self._save_as()

    def _save_as(self):
        if self.cleaned_data is None:
            messagebox.showinfo("No Cleaned Data",
                                 "Run 'Clean Selected' first.")
            return

        # Default name: original_cleaned.skse
        if self.file_path:
            dir_name = os.path.dirname(self.file_path)
            base = os.path.basename(self.file_path)
            name, ext = os.path.splitext(base)
            default_name = f"{name}_cleaned{ext}"
        else:
            dir_name = os.path.expanduser("~\\Desktop")
            default_name = "cleaned.skse"

        path = filedialog.asksaveasfilename(
            title="Save Cleaned Co-Save",
            initialdir=dir_name,
            initialfile=default_name,
            filetypes=[("SKSE Co-Saves", "*.skse"), ("All Files", "*.*")],
            defaultextension=".skse")

        if not path:
            return

        try:
            with open(path, 'wb') as f:
                f.write(self.cleaned_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write file:\n{e}")
            self._set_status("Save failed")
            return

        self._set_status(
            f"Saved: {os.path.basename(path)} "
            f"({format_size(len(self.cleaned_data))})")
        messagebox.showinfo(
            "Saved",
            f"Cleaned co-save written to:\n{path}\n\n"
            f"Size: {format_size(len(self.cleaned_data))} "
            f"(was {format_size(len(self.raw_data))})")

    # ── Status Bar ────────────────────────────────────────────────────────

    def _set_status(self, text):
        self.lbl_status.configure(text=text)


# ─── STRL Editor Dialog ──────────────────────────────────────────────────────

class STRLEditorDialog:
    """Dialog for viewing and selectively removing entries within a STRL chunk."""

    SIZE_WARN = 100_000     # 100K items
    SIZE_BLOAT = 1_000_000  # 1M items

    def __init__(self, parent_app, plugin_idx, chunk_idx):
        self.app = parent_app
        self.pi = plugin_idx
        self.ci = chunk_idx
        self.chunk = parent_app.plugins[plugin_idx]['chunks'][chunk_idx]
        self.entries = None
        self.checked = {}   # (obj_idx, key_idx) -> BooleanVar
        self.result = None  # rebuilt bytes if applied

        self.dialog = tk.Toplevel(parent_app.root)
        self.dialog.title("Edit STRL Entries")
        self.dialog.geometry("900x600")
        self.dialog.minsize(600, 400)
        self.dialog.configure(bg=BG)
        self.dialog.transient(parent_app.root)
        self.dialog.grab_set()

        # Dark title bar on Windows 11
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.dialog.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass

        self._build_ui()
        # Defer parsing so dialog is visible first
        self.dialog.after(50, self._parse_data)

    def _build_ui(self):
        # Info label
        info = ttk.Label(self.dialog,
            text="Select STRL entries to remove. Unchecked entries will be preserved.",
            style="Dim.TLabel", padding=(8, 6))
        info.pack(fill=tk.X)

        ttk.Separator(self.dialog, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Treeview
        tree_frame = ttk.Frame(self.dialog)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self.tree = ttk.Treeview(tree_frame,
            columns=("items", "size", "check"),
            selectmode="browse", show="tree headings")

        self.tree.heading("#0", text="Entry / Key", anchor=tk.W)
        self.tree.heading("items", text="Items", anchor=tk.E)
        self.tree.heading("size", text="Size", anchor=tk.E)
        self.tree.heading("check", text="Del?", anchor=tk.CENTER)

        self.tree.column("#0", width=350, minwidth=150)
        self.tree.column("items", width=140, minwidth=80, anchor=tk.E)
        self.tree.column("size", width=120, minwidth=70, anchor=tk.E)
        self.tree.column("check", width=50, minwidth=40, anchor=tk.CENTER)

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                     command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Button-1>", self._on_click)

        # Tag configs
        self.tree.tag_configure("bloat", foreground=DANGER)
        self.tree.tag_configure("warn", foreground=WARNING)
        self.tree.tag_configure("normal", foreground=FG)
        self.tree.tag_configure("object", foreground=FG_HEADER)
        self.tree.tag_configure("checked", foreground=DANGER)

        ttk.Separator(self.dialog, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Bottom bar
        bottom = ttk.Frame(self.dialog, padding=(8, 6))
        bottom.pack(fill=tk.X)

        self.lbl_status = ttk.Label(bottom, text="Parsing STRL data...",
                                     style="Dim.TLabel")
        self.lbl_status.pack(side=tk.LEFT)

        ttk.Button(bottom, text="Cancel",
                    command=self.dialog.destroy).pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_apply = ttk.Button(bottom, text="Remove Selected",
                                     style="Danger.TButton",
                                     command=self._apply,
                                     state=tk.DISABLED)
        self.btn_apply.pack(side=tk.RIGHT, padx=(4, 0))

    def _parse_data(self):
        self.dialog.update_idletasks()

        try:
            self.entries = parse_strl_structure(self.chunk['raw_data'])
        except Exception as e:
            messagebox.showerror("Parse Error",
                f"Failed to parse STRL data:\n{e}",
                parent=self.dialog)
            self.lbl_status.configure(text="Parse failed")
            return

        self._populate_tree()
        self._update_status()

    def _populate_tree(self):
        for oi, entry in enumerate(self.entries):
            obj_key = entry['obj_key']
            if obj_key == 0:
                obj_label = "None (global)"
            else:
                obj_label = f"Form 0x{obj_key:08X}"

            total_items = sum(k['list_size'] for k in entry['keys'])
            total_bytes = sum(k['byte_size'] for k in entry['keys'])

            obj_id = self.tree.insert(
                "", tk.END, iid=f"o{oi}",
                text=obj_label,
                values=(f"{total_items:,}", format_size(total_bytes), ""),
                tags=("object",),
                open=True)

            for ki, key in enumerate(entry['keys']):
                key_name = f'"{key["name"]}"' if key['name'] else '""  (empty)'

                tags = []
                if key['list_size'] >= self.SIZE_BLOAT:
                    tags.append("bloat")
                elif key['list_size'] >= self.SIZE_WARN:
                    tags.append("warn")
                else:
                    tags.append("normal")

                var = tk.BooleanVar(value=False)
                self.checked[(oi, ki)] = var

                self.tree.insert(
                    obj_id, tk.END, iid=f"k{oi}_{ki}",
                    text=f"    {key_name}",
                    values=(f"{key['list_size']:,}",
                            format_size(key['byte_size']), "\u2610"),
                    tags=tuple(tags))

    def _on_click(self, event):
        col = self.tree.identify_column(event.x)
        item_id = self.tree.identify_row(event.y)

        if not item_id:
            return

        # Check column is #3 (Del?)
        if col == "#3" and item_id.startswith("k"):
            parts = item_id[1:].split("_")
            oi, ki = int(parts[0]), int(parts[1])
            key = (oi, ki)
            if key in self.checked:
                var = self.checked[key]
                var.set(not var.get())
                self._update_check_display(item_id, oi, ki, var.get())
                self._update_status()
        elif col == "#3" and item_id.startswith("o"):
            oi = int(item_id[1:])
            # Toggle all keys under this object
            any_unchecked = any(
                not self.checked.get((oi, ki), tk.BooleanVar()).get()
                for ki in range(len(self.entries[oi]['keys'])))

            for ki in range(len(self.entries[oi]['keys'])):
                key = (oi, ki)
                if key in self.checked:
                    self.checked[key].set(any_unchecked)
                    self._update_check_display(f"k{oi}_{ki}", oi, ki, any_unchecked)

            self._update_status()

    def _update_check_display(self, item_id, oi, ki, is_checked):
        symbol = "\u2611" if is_checked else "\u2610"
        vals = list(self.tree.item(item_id, "values"))
        vals[2] = symbol
        self.tree.item(item_id, values=tuple(vals))

        key = self.entries[oi]['keys'][ki]
        if is_checked:
            tags = ("checked",)
        elif key['list_size'] >= self.SIZE_BLOAT:
            tags = ("bloat",)
        elif key['list_size'] >= self.SIZE_WARN:
            tags = ("warn",)
        else:
            tags = ("normal",)
        self.tree.item(item_id, tags=tags)

    def _update_status(self):
        count = 0
        total_items = 0
        total_bytes = 0

        for (oi, ki), var in self.checked.items():
            if var.get():
                key = self.entries[oi]['keys'][ki]
                count += 1
                total_items += key['list_size']
                total_bytes += key['byte_size']

        if count > 0:
            self.lbl_status.configure(
                text=f"Selected: {count} entr{'ies' if count != 1 else 'y'} "
                     f"({total_items:,} items, ~{format_size(total_bytes)})")
            self.btn_apply.configure(state=tk.NORMAL)
        else:
            total_keys = sum(len(e['keys']) for e in self.entries)
            self.lbl_status.configure(
                text=f"{len(self.entries)} objects, {total_keys} keys total")
            self.btn_apply.configure(state=tk.DISABLED)

    def _apply(self):
        remove_set = {(oi, ki) for (oi, ki), var in self.checked.items()
                      if var.get()}

        if not remove_set:
            return

        # Build summary
        lines = []
        total_items = 0
        for oi, ki in sorted(remove_set):
            entry = self.entries[oi]
            key = entry['keys'][ki]
            obj_label = "None" if entry['obj_key'] == 0 \
                else f"0x{entry['obj_key']:08X}"
            key_label = f'"{key["name"]}"' if key['name'] else '""'
            lines.append(
                f"  {obj_label} / {key_label}: "
                f"{key['list_size']:,} items")
            total_items += key['list_size']

        summary = "\n".join(lines)
        if not messagebox.askyesno("Confirm STRL Entry Removal",
            f"Remove {len(remove_set)} STRL "
            f"entr{'ies' if len(remove_set) != 1 else 'y'} "
            f"({total_items:,} items total)?\n\n"
            f"{summary}\n\n"
            f"Other entries will be preserved.",
            parent=self.dialog):
            return

        # Rebuild STRL data
        self.lbl_status.configure(text="Rebuilding STRL data...")
        self.dialog.update_idletasks()

        try:
            self.result = rebuild_strl_data(
                self.chunk['raw_data'], self.entries, remove_set)
        except Exception as e:
            messagebox.showerror("Error",
                f"Failed to rebuild STRL data:\n{e}",
                parent=self.dialog)
            self.lbl_status.configure(text="Rebuild failed")
            return

        self.dialog.destroy()


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()

    # Set dark title bar on Windows 11
    try:
        import ctypes
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
    except Exception:
        pass

    app = CosaveCleanerApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
