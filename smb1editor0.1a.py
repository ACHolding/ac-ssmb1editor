"""
SMB1 Utility Clone — Blue Hue Edition (Python 3.14 optimized)
No asset files required. Pure tkinter UI.
"""

from __future__ import annotations

import re
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Final

# --- AESTHETIC CONFIGURATION ---
COLOR_BG: Final[str] = "#000000"
COLOR_FG: Final[str] = "#00BFFF"
COLOR_ACCENT: Final[str] = "#0077BE"
COLOR_BTN_BG: Final[str] = "#001122"
FONT_MAIN: Final[tuple[str, int]] = ("Consolas", 10)
FONT_HEADER: Final[tuple[str, int]] = ("Consolas", 12, "bold")

# --- NES/SMB1 MEMORY MAP CONSTANTS ---
INES_MAGIC: Final[bytes] = b"NES\x1a"
INES_HEADER_SIZE: Final[int] = 16
SMB1_PRG_BANKS: Final[int] = 2
SMB1_CHR_BANKS: Final[int] = 1
SMB1_PRG_SIZE: Final[int] = SMB1_PRG_BANKS * 16384
SMB1_CHR_SIZE: Final[int] = SMB1_CHR_BANKS * 8192
SMB1_BODY_SIZE: Final[int] = SMB1_PRG_SIZE + SMB1_CHR_SIZE
SMB1_SIZES: Final[tuple[int, int]] = (SMB1_BODY_SIZE, SMB1_BODY_SIZE + INES_HEADER_SIZE)

TEXT_OFFSETS_PRG: Final[dict[str, tuple[int, int]]] = {
    "MARIO": (0x0765, 5),
    "LUIGI": (0x07FD, 5),
    "WORLD": (0x076D, 5),
    "TIME": (0x0774, 4),
}
LEVEL_HEADER_START_PRG: Final[int] = 0x1CCC
LEVEL_HEADER_BYTES: Final[int] = 4 * 36
SMB_WORLD_SETTING: Final[int] = 0x9CB4
SMB_AREA_SETTING: Final[int] = 0x9CBC
SMB_BADGUYS_ADDRESS_LOW: Final[int] = 0x9CE4
SMB_BADGUYS_ADDRESS_HIGH: Final[int] = 0x9D06
SMB_MAP_ADDRESS_LOW: Final[int] = 0x9D2C
SMB_MAP_ADDRESS_HIGH: Final[int] = 0x9D4E
PALETTE_PRG: Final[int] = 0x85B7
PALETTE_LEN: Final[int] = 32


def prg_to_file_offset(prg_addr: int, has_ines: bool) -> int:
    """Translates a NES CPU PRG-ROM memory address into a raw file array offset."""
    base = INES_HEADER_SIZE if has_ines else 0
    if prg_addr < 0x8000:
        return base + prg_addr
    return base + 0x4000 + (prg_addr - 0x8000)


def smb_encode(text: str, length: int) -> bytes:
    """Encodes standard ASCII strings into original SMB1 HUD character bytes."""
    char_map: dict[str, int] = {str(d): d for d in range(10)}
    for i in range(26):
        char_map[chr(ord("A") + i)] = 0x0A + i
    char_map.update({" ": 0x24, "-": 0x28, "!": 0x2B, ".": 0xAF})
    pad = 0x24
    out = bytearray()
    for ch in text.upper()[:length]:
        out.append(char_map.get(ch, pad))
    while len(out) < length:
        out.append(pad)
    return bytes(out)


def smb_decode(raw: bytes) -> str:
    """Decodes original SMB1 HUD character bytes back to readable text strings."""
    base_map = {
        **{str(d): d for d in range(10)},
        **{chr(ord("A") + i): 0x0A + i for i in range(26)},
        " ": 0x24, "-": 0x28, "!": 0x2B, ".": 0xAF,
    }
    rev = {v: k for k, v in base_map.items()}
    return "".join(rev.get(b, ".") for b in raw).rstrip()


def validate_and_load(path: str) -> tuple[bytearray, bool]:
    """Validates the structure, integrity, and mapper specifications of an inbound ROM."""
    data = Path(path).read_bytes()
    has_ines = len(data) >= 4 and data[:4] == INES_MAGIC
    if has_ines:
        if len(data) < INES_HEADER_SIZE:
            raise ValueError("Truncated iNES header structural metadata.")
        prg_banks = data[4]
        chr_banks = data[5]
        if prg_banks != SMB1_PRG_BANKS or chr_banks != SMB1_CHR_BANKS:
            raise ValueError(
                f"Expected SMB1 mapper configuration (PRG={SMB1_PRG_BANKS}, CHR={SMB1_CHR_BANKS}), "
                f"but found PRG={prg_banks}, CHR={chr_banks} instead."
            )
        expected = INES_HEADER_SIZE + prg_banks * 16384 + chr_banks * 8192
        if len(data) != expected:
            raise ValueError(f"ROM structural violation: Payload footprint ({len(data)}) matches no standard sizing targets.")
    elif len(data) != SMB1_BODY_SIZE:
        raise ValueError(
            f"Raw headerless ROM must scale to exactly {SMB1_BODY_SIZE} bytes."
        )
    return bytearray(data), has_ines


class SMB1Rom:
    def __init__(self, rom: bytearray, has_ines: bool) -> None:
        self.rom = rom
        self.has_ines = has_ines

    def read_prg(self, addr: int, size: int) -> bytes:
        start = prg_to_file_offset(addr, self.has_ines)
        end = start + size
        if start < 0 or end > len(self.rom):
            raise ValueError(f"Read operation outbound limit error: PRG ${addr:04X} bounds size limit {size}")
        return bytes(self.rom[start:end])

    def write_prg(self, addr: int, data: bytes) -> None:
        start = prg_to_file_offset(addr, self.has_ines)
        end = start + len(data)
        if start < 0 or end > len(self.rom):
            raise ValueError(f"Write operation outbound limit error: PRG ${addr:04X} bounds size limit {len(data)}")
        self.rom[start:end] = data

    def prg_checksum(self) -> int:
        start = prg_to_file_offset(0x8000, self.has_ines)
        return sum(self.rom[start : start + SMB1_PRG_SIZE]) & 0xFFFFFFFF

    def pointer(self, low_prg: int, hi_prg: int, index: int) -> int:
        lo = prg_to_file_offset(low_prg + index, self.has_ines)
        hi = prg_to_file_offset(hi_prg + index, self.has_ines)
        return self.rom[lo] | (self.rom[hi] << 8)

    def dump_level_data(self) -> str:
        world = self.read_prg(SMB_WORLD_SETTING, 8)
        areas = self.read_prg(SMB_AREA_SETTING, 36)
        headers = self.read_prg(LEVEL_HEADER_START_PRG, LEVEL_HEADER_BYTES)
        lines = [
            f"World Settings Block @ ${SMB_WORLD_SETTING:04X}: {world.hex(' ')}",
            f"Area Lookup Sequence Matrix @ ${SMB_AREA_SETTING:04X}:",
        ]
        for i, b in enumerate(areas):
            lines.append(f"  Area index reference [{i:02d}]: Value 0x{b:02X} (Map-Room assigned: {b & 0x7F})")
        lines.append(f"\nLevel Object State Profile Blocks @ ${LEVEL_HEADER_START_PRG:04X}:")
        for i in range(0, len(headers), 4):
            chunk = headers[i : i + 4]
            lines.append(f"  Header profile sequence [{i // 4:02d}]: {chunk.hex(' ')}")
        map0 = self.pointer(SMB_MAP_ADDRESS_LOW, SMB_MAP_ADDRESS_HIGH, 0)
        lines.append(f"\nArea Base Pointer Address Zero Origin Map: ${map0:04X}")
        lines.append("\nEdit instructions: Format entries explicitly as 'Area XX: 0xYY' or 'Header XX: YY YY YY YY'")
        return "\n".join(lines)

    def apply_level_data(self, text: str) -> int:
        count = 0
        areas = bytearray(self.read_prg(SMB_AREA_SETTING, 36))
        headers = bytearray(self.read_prg(LEVEL_HEADER_START_PRG, LEVEL_HEADER_BYTES))
        
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if match := re.match(r"Area\s+index\s+reference\s+\[(\d+)\]:\s+Value\s+0x([0-9A-Fa-f]+)", line):
                idx, val = int(match.group(1)), int(match.group(2), 16)
                if 0 <= idx < len(areas):
                    areas[idx] = val & 0xFF
                    count += 1
            elif match := re.match(r"Header\s+profile\s+sequence\s+\[(\d+)\]:\s+([0-9A-Fa-f\s]+)", line):
                idx = int(match.group(1))
                bytes_vals = [int(x, 16) for x in match.group(2).split()]
                if 0 <= idx * 4 < len(headers) and len(bytes_vals) == 4:
                    headers[idx*4 : idx*4 + 4] = bytes_vals
                    count += 1
                    
        if count > 0:
            self.write_prg(SMB_AREA_SETTING, bytes(areas))
            self.write_prg(LEVEL_HEADER_START_PRG, bytes(headers))
        return count

    def dump_enemies(self) -> str:
        lines = ["Enemy Assignment Structural Pointer Map Data (Pointers for Areas 00-11):"]
        for i in range(12):
            addr = self.pointer(SMB_BADGUYS_ADDRESS_LOW, SMB_BADGUYS_ADDRESS_HIGH, i)
            lines.append(f"  Area layout target pointer [{i:02d}]: ${addr:04X}")
        addr0 = self.pointer(SMB_BADGUYS_ADDRESS_LOW, SMB_BADGUYS_ADDRESS_HIGH, 0)
        off = prg_to_file_offset(addr0, self.has_ines)
        raw = bytes(self.rom[off : min(off + 48, len(self.rom))])
        lines.append(f"\nRaw hex dump around base Area 00 stream offset (${addr0:04X}):")
        for i in range(0, len(raw), 16):
            lines.append(f"  Raw chunk offsets (+{i:02X}): {raw[i : i + 16].hex(' ')}")
        lines.append("\nEdit instructions: Alter raw layout data array via direct byte stream edits:")
        lines.append(f"Data Stream @ ${addr0:04X} = {raw.hex(' ')}")
        return "\n".join(lines)

    def apply_enemies(self, text: str) -> int:
        count = 0
        addr0 = self.pointer(SMB_BADGUYS_ADDRESS_LOW, SMB_BADGUYS_ADDRESS_HIGH, 0)
        for line in text.splitlines():
            line = line.strip()
            if f"Data Stream @ ${addr0:04X} =" in line:
                hex_part = line.partition("=")[2].strip()
                try:
                    raw_bytes = bytes.fromhex(hex_part)
                    if raw_bytes:
                        self.write_prg(addr0, raw_bytes)
                        count += 1
                except ValueError:
                    continue
        return count

    def dump_palette(self) -> str:
        raw = self.read_prg(PALETTE_PRG, PALETTE_LEN)
        lines = [f"System Direct Hardware Palette Block Profile Data @ ${PALETTE_PRG:04X}:"]
        for i in range(0, len(raw), 8):
            lines.append(f"  Palette color group index sequence [{i // 8:01d}]: {raw[i : i + 8].hex(' ')}")
        lines.append("\nEdit instructions: Alter system palette records using direct structural block syntax:")
        lines.append(f"Master Palette Index Stream Block = {raw.hex(' ')}")
        return "\n".join(lines)

    def apply_palette(self, text: str) -> int:
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if "Master Palette Index Stream Block =" in line:
                hex_part = line.partition("=")[2].strip()
                try:
                    raw_bytes = bytes.fromhex(hex_part)
                    if len(raw_bytes) == PALETTE_LEN:
                        self.write_prg(PALETTE_PRG, raw_bytes)
                        count += 1
                except ValueError:
                    continue
        return count

    def dump_text(self) -> str:
        lines = ["Active HUD String Mapping Arrays (Decoded System Characters):"]
        for name, (addr, length) in TEXT_OFFSETS_PRG.items():
            raw = self.read_prg(addr, length)
            lines.append(f"  {name}={smb_decode(raw)}")
        lines.append("\nEdit instructions: Modify entries as KeyName=Value (Max: 5 chars length limit targets).")
        return "\n".join(lines)

    def apply_text(self, text: str) -> int:
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip().upper()
            val = val.strip().upper()
            if key not in TEXT_OFFSETS_PRG:
                continue
            addr, length = TEXT_OFFSETS_PRG[key]
            self.write_prg(addr, smb_encode(val, length))
            count += 1
        return count

    def dump_checksum(self) -> str:
        csum = self.prg_checksum()
        return (
            f"PRG Sum validation footprint calculation: 0x{csum:08X} ({csum})\n"
            f"Active localized structural system size: {len(self.rom)} bytes\n"
            f"Active iNES structural layout headers: {'Detected and Parsed' if self.has_ines else 'Missing/Raw Mapping Layer'}"
        )


class SMB1EditorGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("smb1 editor by ac 0.1")
        self.root.configure(bg=COLOR_BG)
        self.root.geometry("860x660")
        self.root.minsize(700, 500)

        self.rom_path: Path | None = None
        self.engine: SMB1Rom | None = None
        self.modified = False
        self.tab_views: dict[str, scrolledtext.ScrolledText] = {}
        self.tab_writable: dict[str, bool] = {}

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Blue.TFrame", background=COLOR_BG)
        style.configure("Blue.TLabel", background=COLOR_BG, foreground=COLOR_FG, font=FONT_MAIN)
        style.configure("Blue.Header.TLabel", background=COLOR_BG, foreground=COLOR_FG, font=FONT_HEADER)
        style.configure(
            "Blue.TButton",
            background=COLOR_BTN_BG,
            foreground=COLOR_FG,
            bordercolor=COLOR_ACCENT,
            font=FONT_MAIN,
            padding=8,
        )
        style.map("Blue.TButton", background=[("active", COLOR_ACCENT)])
        style.configure("Blue.TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure(
            "Blue.TNotebook.Tab",
            background=COLOR_BTN_BG,
            foreground=COLOR_FG,
            padding=[12, 4],
        )
        style.map("Blue.TNotebook.Tab", background=[("selected", COLOR_ACCENT)])

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, style="Blue.TFrame")
        main.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(
            main,
            text="SUPER MARIO BROS. 1 // INTEGRATED CORE HARDWARE ENGINE UTILITY",
            style="Blue.Header.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        file_row = ttk.Frame(main, style="Blue.TFrame")
        file_row.pack(fill=tk.X, pady=(0, 12))
        self.path_var = tk.StringVar(value="[SYSTEM STATUS: EMPTY ROM ENGINE FILE BUFFER]")
        
        path_lbl = tk.Label(
            file_row,
            textvariable=self.path_var,
            bg=COLOR_BG,
            fg=COLOR_FG,
            font=FONT_MAIN,
            anchor=tk.W,
            relief=tk.SUNKEN,
            bd=1,
            padx=8,
            pady=6,
        )
        path_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ttk.Button(file_row, text="LOAD ROM FILE", style="Blue.TButton", command=self.load_rom).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(file_row, text="SAVE ROM CHANGES", style="Blue.TButton", command=self.save_rom).pack(
            side=tk.LEFT
        )

        notebook = ttk.Notebook(main, style="Blue.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # All tabs set to True to unleash engine features
        for tab_name, writable in (
            ("Level Data", True),
            ("Enemy Placements", True),
            ("Palette Editor", True),
            ("Text/HUD", True),
            ("Checksum", False),
        ):
            frame = ttk.Frame(notebook, style="Blue.TFrame")
            notebook.add(frame, text=f" {tab_name} ")
            self._build_tab(frame, tab_name, writable)

        self.status_var = tk.StringVar(value="ENGINE ONLINE // PARSING AND VALIDATION INTERACTION CHANNELS OPEN")
        ttk.Label(main, textvariable=self.status_var, style="Blue.TLabel").pack(anchor=tk.W, pady=(8, 0))

    def _build_tab(self, parent: ttk.Frame, name: str, writable: bool) -> None:
        ttk.Label(parent, text=f"{name.upper()} SUBPROCESS SYSTEM CONTROL MODULE", style="Blue.Header.TLabel").pack(
            anchor=tk.W, padx=10, pady=(8, 4)
        )
        btn_row = ttk.Frame(parent, style="Blue.TFrame")
        btn_row.pack(anchor=tk.W, padx=10, pady=(0, 6))
        
        ttk.Button(
            btn_row,
            text="READ FROM ENGINE",
            style="Blue.TButton",
            command=lambda n=name: self.read_tab(n),
        ).pack(side=tk.LEFT, padx=(0, 6))
        
        write_btn = ttk.Button(
            btn_row,
            text="PATCH TO ENGINE",
            style="Blue.TButton",
            command=lambda n=name: self.write_tab(n),
        )
        write_btn.pack(side=tk.LEFT)
        if not writable:
            write_btn.configure(state=tk.DISABLED)

        txt = scrolledtext.ScrolledText(
            parent,
            height=16,
            bg=COLOR_BG,
            fg=COLOR_FG,
            insertbackground=COLOR_FG,
            selectbackground=COLOR_ACCENT,
            selectforeground=COLOR_FG,
            font=FONT_MAIN,
            relief=tk.SUNKEN,
            bd=1,
            wrap=tk.WORD,
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.tab_views[name] = txt
        self.tab_writable[name] = writable

    def _require_rom(self) -> SMB1Rom | None:
        if self.engine is None:
            messagebox.showwarning("HARDWARE CACHE EMPTY", "Please load a verified target SMB1 .nes ROM image.")
            return None
        return self.engine

    def load_rom(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Targeted SMB1 ROM Block File",
            filetypes=[("NES ROM Files", "*.nes"), ("All Unified Assets", "*.*")],
        )
        if not path:
            return
        try:
            rom, has_ines = validate_and_load(path)
            self.engine = SMB1Rom(rom, has_ines)
            self.rom_path = Path(path)
            self.modified = False
            self.path_var.set(str(self.rom_path.name))
            hdr = "iNES Managed Layer" if has_ines else "Raw Map Unchecked Format"
            self.status_var.set(
                f"LOAD SUCCESS: {self.rom_path.name} // File footprint: {len(rom)} bytes // Format: {hdr}"
            )
            # Cascade standard read down line buffers automatically on setup
            for tab in self.tab_views:
                self.read_tab(tab)
        except OSError as exc:
            messagebox.showerror("OS FILE BOUND INTERRUPT", str(exc))
            self.status_var.set("SYSTEM EXCEPTION: UNABLE TO ACCESS AND ALLOCATE MEMORY PROFILE")
        except ValueError as exc:
            messagebox.showerror("VALIDATION FAILURE", str(exc))
            self.status_var.set("SYSTEM EXCEPTION: ARCHITECTURAL DEVIATION COMPATIBILITY FAULT")

    def save_rom(self) -> None:
        eng = self._require_rom()
        if eng is None or self.rom_path is None:
            return
        path = filedialog.asksaveasfilename(
            title="Export Working Subsystem ROM Changes",
            initialfile=self.rom_path.name,
            defaultextension=".nes",
            filetypes=[("NES ROM Compiled Format", "*.nes"), ("All Compiled Output Blocks", "*.*")],
        )
        if not path:
            return
        try:
            Path(path).write_bytes(eng.rom)
            self.rom_path = Path(path)
            self.modified = False
            self.path_var.set(self.rom_path.name)
            self.status_var.set(f"EXPORT CONFIRMED: Hex data serialized to target layout disk: {self.rom_path.name}")
        except OSError as exc:
            messagebox.showerror("SERIALIZATION TERMINATED", str(exc))

    def read_tab(self, name: str) -> None:
        eng = self._require_rom()
        if eng is None:
            return
        readers = {
            "Level Data": eng.dump_level_data,
            "Enemy Placements": eng.dump_enemies,
            "Palette Editor": eng.dump_palette,
            "Text/HUD": eng.dump_text,
            "Checksum": eng.dump_checksum,
        }
        try:
            body = readers[name]()
        except ValueError as exc:
            messagebox.showerror("PARSE EXECUTION EXCEPTION", str(exc))
            return
        txt = self.tab_views[name]
        txt.configure(state=tk.NORMAL)
        txt.delete("1.0", tk.END)
        txt.insert("1.0", body)
        self.status_var.set(f"IO FETCH COMPLETED // PIPELINE MODULE INGESTED: {name.upper()}")

    def write_tab(self, name: str) -> None:
        if not self.tab_writable.get(name, False):
            messagebox.showinfo("PROTECTED PIPELINE BOUNDS", f"The data processing routine for {name} is view-only.")
            return
        eng = self._require_rom()
        if eng is None:
            return
        body = self.tab_views[name].get("1.0", tk.END)
        try:
            match name:
                case "Text/HUD":
                    n = eng.apply_text(body)
                case "Level Data":
                    n = eng.apply_level_data(body)
                case "Enemy Placements":
                    n = eng.apply_enemies(body)
                case "Palette Editor":
                    n = eng.apply_palette(body)
                case _:
                    return
                    
            if n == 0:
                messagebox.showwarning(
                    "TRANSLATION BOUNDARY ZERO EXCEPTION",
                    "No structured text fields matched parser syntax parameters. Check alignment configurations."
                )
                return
        except ValueError as exc:
            messagebox.showerror("HARDWARE ADAPTER PATCH FAILURE", str(exc))
            return
            
        self.modified = True
        self.status_var.set(f"SYSTEM DATA PATCH SUCCESS // PIPELINE STREAM COMMITTED: {name.upper()} ({n} item(s) mapped)")
        self.read_tab(name)


def main() -> None:
    root = tk.Tk()
    if sys.platform == "win32":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    SMB1EditorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
