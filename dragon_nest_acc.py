"""
Game Account Tracker
=====================
Aplikasi GUI untuk mengelola banyak akun game beserta info karakter
(nama, level, job) dan status clear dungeon (Nest & Dragon Fellowship).

Setiap akun (char_id) bisa memiliki BANYAK HERO / karakter.

Keamanan:
- Saat aplikasi dibuka, wajib login dengan MASTER PASSWORD (dibuat sendiri
  saat pertama kali menjalankan aplikasi).
- Password tiap akun game DIENKRIPSI (bukan disimpan polos/plain text)
  menggunakan kunci yang diturunkan dari master password kamu.
- Semua data disimpan lokal di folder "data/" di sebelah file ini.

Cara pakai:
    pip install cryptography
    python game_account_tracker.py

PENTING: Kalau lupa master password, password akun yang tersimpan TIDAK
BISA dipulihkan (karena memang sengaja dienkripsi). Simpan master
password kamu baik-baik.
"""

import os
import json
import copy
import base64
import hashlib
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Konfigurasi path penyimpanan data
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")

os.makedirs(DATA_DIR, exist_ok=True)

# Struktur default dungeon yang dilacak
DEFAULT_DUNGEON = {
    "nest": {
        "PKN_HC": False,
        "TKN_HC": False,
        "Guardian": False,
    },
    "dragon_fellowship": {
        "Dragon_Expedition_Lv60": False,
        "Dragon_Expedition_Lv70": False,
    },
}

NEST_LABELS = [("PKN_HC", "PKN HC"), ("TKN_HC", "TKN HC"), ("Guardian", "Guardian")]
DRAGON_LABELS = [
    ("Dragon_Expedition_Lv60", "DF Lv.60"),
    ("Dragon_Expedition_Lv70", "DF Lv.70"),
]


# ---------------------------------------------------------------------------
# Fungsi bantu kriptografi
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Menurunkan kunci enkripsi Fernet dari master password + salt."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def hash_password(password: str, salt: bytes) -> str:
    """Hash password untuk verifikasi login (bukan untuk enkripsi data)."""
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Pengelola konfigurasi (master password)
# ---------------------------------------------------------------------------
class ConfigManager:
    def __init__(self):
        self.data = None
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                self.data = json.load(f)

    def is_configured(self) -> bool:
        return self.data is not None

    def setup_master_password(self, password: str):
        auth_salt = secrets.token_bytes(16)
        enc_salt = secrets.token_bytes(16)
        self.data = {
            "auth_salt": base64.b64encode(auth_salt).decode(),
            "enc_salt": base64.b64encode(enc_salt).decode(),
            "password_hash": hash_password(password, auth_salt),
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def verify_password(self, password: str) -> bool:
        auth_salt = base64.b64decode(self.data["auth_salt"])
        return hash_password(password, auth_salt) == self.data["password_hash"]

    def get_enc_key(self, password: str) -> bytes:
        enc_salt = base64.b64decode(self.data["enc_salt"])
        return derive_key(password, enc_salt)

    def change_password(self, new_password: str):
        # Salt enkripsi baru + re-enkripsi seluruh password akun dilakukan
        # di level aplikasi (lihat App.change_master_password).
        auth_salt = base64.b64decode(self.data["auth_salt"])
        self.data["password_hash"] = hash_password(new_password, auth_salt)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)


# ---------------------------------------------------------------------------
# Pengelola data akun  (MULTI-HERO)
# ---------------------------------------------------------------------------
class AccountManager:
    """
    Struktur data baru per akun:
    {
        "char_id": "...",
        "password_enc": "...",
        "characters": [
            {
                "char_name": "...",
                "char_lvl": 80,
                "char_job": "...",
                "dungeon": { ... }
            },
            ...   # bisa banyak hero dalam satu akun
        ]
    }

    Format lama (tanpa "characters") otomatis dimigrasi saat load.
    """

    def __init__(self, fernet: Fernet):
        self.fernet = fernet
        self.accounts: list[dict] = []
        self.load()

    # --- migrasi format lama → baru ------------------------------------------
    @staticmethod
    def _migrate_if_needed(acc: dict) -> dict:
        """Konversi format lama (flat) ke format baru (characters list)."""
        if "characters" not in acc:
            char = {
                "char_name": acc.pop("char_name", ""),
                "char_lvl": acc.pop("char_lvl", 1),
                "char_job": acc.pop("char_job", ""),
                "dungeon": acc.pop("dungeon", copy.deepcopy(DEFAULT_DUNGEON)),
            }
            acc["characters"] = [char]
        return acc

    # --- I/O -----------------------------------------------------------------
    def load(self):
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            migrated = False
            for i, acc in enumerate(raw):
                if "characters" not in acc:
                    raw[i] = self._migrate_if_needed(acc)
                    migrated = True
            self.accounts = raw
            if migrated:
                self.save()  # simpan ulang agar format baru tersimpan
        else:
            self.accounts = []

    def save(self):
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.accounts, f, indent=2, ensure_ascii=False)

    # --- enkripsi / dekripsi --------------------------------------------------
    def encrypt_password(self, plain: str) -> str:
        return self.fernet.encrypt(plain.encode("utf-8")).decode("utf-8")

    def decrypt_password(self, token: str) -> str:
        try:
            return self.fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return "<gagal dekripsi>"

    # --- cari akun ------------------------------------------------------------
    def find_index(self, char_id: str):
        for i, acc in enumerate(self.accounts):
            if acc["char_id"] == char_id:
                return i
        return None

    # --- operasi akun ---------------------------------------------------------
    def add_account(self, char_id: str, password: str, char_name: str,
                    char_lvl: int, char_job: str, dungeon: dict):
        """Tambah akun baru dengan satu hero awal."""
        self.accounts.append({
            "char_id": char_id,
            "password_enc": self.encrypt_password(password),
            "characters": [{
                "char_name": char_name,
                "char_lvl": char_lvl,
                "char_job": char_job,
                "dungeon": dungeon,
            }],
        })
        self.save()

    def update_account_credentials(self, index: int, char_id: str, password: str | None):
        """Update char_id dan/atau password akun (tanpa menyentuh hero)."""
        acc = self.accounts[index]
        acc["char_id"] = char_id
        if password is not None:
            acc["password_enc"] = self.encrypt_password(password)
        self.save()

    def delete_account(self, index: int):
        del self.accounts[index]
        self.save()

    # --- operasi hero ---------------------------------------------------------
    def add_hero(self, account_index: int, char_name: str, char_lvl: int,
                 char_job: str, dungeon: dict):
        """Tambah hero baru ke akun yang sudah ada."""
        self.accounts[account_index]["characters"].append({
            "char_name": char_name,
            "char_lvl": char_lvl,
            "char_job": char_job,
            "dungeon": dungeon,
        })
        self.save()

    def update_hero(self, account_index: int, hero_index: int,
                    char_name: str, char_lvl: int, char_job: str, dungeon: dict):
        """Edit hero yang sudah ada."""
        hero = self.accounts[account_index]["characters"][hero_index]
        hero["char_name"] = char_name
        hero["char_lvl"] = char_lvl
        hero["char_job"] = char_job
        hero["dungeon"] = dungeon
        self.save()

    def delete_hero(self, account_index: int, hero_index: int):
        """Hapus hero tertentu dari akun. Kalau hero terakhir, hapus akun."""
        chars = self.accounts[account_index]["characters"]
        del chars[hero_index]
        if not chars:
            # Hero terakhir dihapus → hapus seluruh akun
            del self.accounts[account_index]
        self.save()

    # --- utilitas tampilan ----------------------------------------------------
    @staticmethod
    def dungeon_summary(dungeon: dict) -> str:
        nest = dungeon.get("nest", {})
        dragon = dungeon.get("dragon_fellowship", {})

        def mark(v):
            return "✓" if v else "✗"

        nest_str = " ".join(f"{label}:{mark(nest.get(key, False))}" for key, label in NEST_LABELS)
        dragon_str = " ".join(f"{label}:{mark(dragon.get(key, False))}" for key, label in DRAGON_LABELS)
        return f"[Nest] {nest_str}  |  [Dragon Fellowship] {dragon_str}"


# ---------------------------------------------------------------------------
# Dialog Tambah / Edit Akun  (hanya char_id + password)
# ---------------------------------------------------------------------------
class AccountDialog(tk.Toplevel):
    """Dialog untuk membuat akun baru (char_id + password + hero pertama)
    atau mengedit kredensial akun yang sudah ada."""

    def __init__(self, master, account_manager: AccountManager, index=None):
        super().__init__(master)
        self.account_manager = account_manager
        self.index = index  # None = tambah baru, angka = edit
        self.result = False

        self.title("Edit Akun" if index is not None else "Tambah Akun")
        self.resizable(False, False)
        self.grab_set()  # modal

        existing = account_manager.accounts[index] if index is not None else None

        pad = {"padx": 8, "pady": 4}

        # --- Char ID ---
        tk.Label(self, text="Character ID:").grid(row=0, column=0, sticky="e", **pad)
        self.char_id_var = tk.StringVar(value=existing["char_id"] if existing else "")
        tk.Entry(self, textvariable=self.char_id_var, width=30).grid(row=0, column=1, columnspan=2, sticky="w", **pad)

        # --- Password ---
        tk.Label(self, text="Password:").grid(row=1, column=0, sticky="e", **pad)
        self.pw_var = tk.StringVar()
        if existing:
            self.pw_var.set("")  # kosong = tidak diubah saat edit
        self.pw_entry = tk.Entry(self, textvariable=self.pw_var, width=30, show="*")
        self.pw_entry.grid(row=1, column=1, sticky="w", **pad)

        self.show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(self, text="Lihat", variable=self.show_pw, command=self.toggle_pw).grid(row=1, column=2, sticky="w")
        if existing:
            tk.Label(self, text="(kosongkan jika tidak ingin mengubah password)", fg="gray").grid(
                row=2, column=1, columnspan=2, sticky="w", padx=8)

        row_offset = 3

        # Untuk akun baru, tampilkan juga form hero pertama
        if index is None:
            tk.Label(self, text="── Hero Pertama ──", font=("", 9, "bold")).grid(
                row=row_offset, column=0, columnspan=3, pady=(10, 2))
            row_offset += 1

            tk.Label(self, text="Nama Karakter:").grid(row=row_offset, column=0, sticky="e", **pad)
            self.name_var = tk.StringVar()
            tk.Entry(self, textvariable=self.name_var, width=30).grid(
                row=row_offset, column=1, columnspan=2, sticky="w", **pad)

            tk.Label(self, text="Level:").grid(row=row_offset + 1, column=0, sticky="e", **pad)
            self.lvl_var = tk.StringVar(value="1")
            tk.Spinbox(self, from_=1, to=999, textvariable=self.lvl_var, width=10).grid(
                row=row_offset + 1, column=1, sticky="w", **pad)

            tk.Label(self, text="Job:").grid(row=row_offset + 2, column=0, sticky="e", **pad)
            self.job_var = tk.StringVar()
            tk.Entry(self, textvariable=self.job_var, width=30).grid(
                row=row_offset + 2, column=1, columnspan=2, sticky="w", **pad)

            # Dungeon: Nest
            nest_frame = tk.LabelFrame(self, text="Nest")
            nest_frame.grid(row=row_offset + 3, column=0, columnspan=3, sticky="we", padx=8, pady=(10, 4))
            self.nest_vars = {}
            for key, label in NEST_LABELS:
                var = tk.BooleanVar(value=False)
                tk.Checkbutton(nest_frame, text=label, variable=var).pack(side="left", padx=6, pady=4)
                self.nest_vars[key] = var

            # Dungeon: Dragon Fellowship
            dragon_frame = tk.LabelFrame(self, text="Dragon Fellowship")
            dragon_frame.grid(row=row_offset + 4, column=0, columnspan=3, sticky="we", padx=8, pady=4)
            self.dragon_vars = {}
            for key, label in DRAGON_LABELS:
                var = tk.BooleanVar(value=False)
                tk.Checkbutton(dragon_frame, text=label, variable=var).pack(side="left", padx=6, pady=4)
                self.dragon_vars[key] = var

            row_offset += 5
        else:
            self.name_var = None  # tidak perlu form hero saat edit kredensial

        # --- Tombol ---
        btn_frame = tk.Frame(self)
        btn_frame.grid(row=row_offset, column=0, columnspan=3, pady=12)
        tk.Button(btn_frame, text="Simpan", width=12, command=self.on_save).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Batal", width=12, command=self.destroy).pack(side="left", padx=6)

    def toggle_pw(self):
        self.pw_entry.config(show="" if self.show_pw.get() else "*")

    def on_save(self):
        char_id = self.char_id_var.get().strip()
        pw = self.pw_var.get()

        if not char_id:
            messagebox.showerror("Error", "Character ID tidak boleh kosong.", parent=self)
            return

        # Cek duplikat char_id
        existing_index = self.account_manager.find_index(char_id)
        if existing_index is not None and existing_index != self.index:
            messagebox.showerror("Error", f"Character ID '{char_id}' sudah dipakai akun lain.", parent=self)
            return

        if self.index is None:
            # --- Tambah akun baru ---
            if not pw:
                messagebox.showerror("Error", "Password tidak boleh kosong untuk akun baru.", parent=self)
                return
            name = self.name_var.get().strip()
            job = self.job_var.get().strip()
            if not name:
                messagebox.showerror("Error", "Nama karakter tidak boleh kosong.", parent=self)
                return
            try:
                lvl = int(self.lvl_var.get())
            except ValueError:
                messagebox.showerror("Error", "Level harus berupa angka.", parent=self)
                return

            dungeon = {
                "nest": {key: var.get() for key, var in self.nest_vars.items()},
                "dragon_fellowship": {key: var.get() for key, var in self.dragon_vars.items()},
            }
            self.account_manager.add_account(char_id, pw, name, lvl, job, dungeon)
        else:
            # --- Edit kredensial akun ---
            self.account_manager.update_account_credentials(
                self.index, char_id, pw if pw else None)

        self.result = True
        self.destroy()


# ---------------------------------------------------------------------------
# Dialog Tambah / Edit Hero  (nama, level, job, dungeon – tanpa char_id/pw)
# ---------------------------------------------------------------------------
class HeroDialog(tk.Toplevel):
    """Dialog untuk menambah hero baru ke akun yang sudah ada,
    atau mengedit hero yang sudah ada."""

    def __init__(self, master, account_manager: AccountManager,
                 account_index: int, hero_index: int | None = None):
        super().__init__(master)
        self.account_manager = account_manager
        self.account_index = account_index
        self.hero_index = hero_index  # None = tambah baru
        self.result = False

        acc = account_manager.accounts[account_index]
        existing_hero = acc["characters"][hero_index] if hero_index is not None else None
        existing_dungeon = (existing_hero["dungeon"]
                            if existing_hero
                            else copy.deepcopy(DEFAULT_DUNGEON))

        self.title(
            f"Edit Hero – {acc['char_id']}" if hero_index is not None
            else f"Tambah Hero – {acc['char_id']}"
        )
        self.resizable(False, False)
        self.grab_set()

        pad = {"padx": 8, "pady": 4}
        row = 0

        # --- Info akun (read-only) ---
        tk.Label(self, text=f"Akun: {acc['char_id']}", font=("", 9, "bold")).grid(
            row=row, column=0, columnspan=3, sticky="w", padx=8, pady=(8, 2))
        row += 1

        # --- Nama, Level, Job ---
        tk.Label(self, text="Nama Karakter:").grid(row=row, column=0, sticky="e", **pad)
        self.name_var = tk.StringVar(value=existing_hero["char_name"] if existing_hero else "")
        tk.Entry(self, textvariable=self.name_var, width=30).grid(
            row=row, column=1, columnspan=2, sticky="w", **pad)

        tk.Label(self, text="Level:").grid(row=row + 1, column=0, sticky="e", **pad)
        self.lvl_var = tk.StringVar(value=str(existing_hero["char_lvl"]) if existing_hero else "1")
        tk.Spinbox(self, from_=1, to=999, textvariable=self.lvl_var, width=10).grid(
            row=row + 1, column=1, sticky="w", **pad)

        tk.Label(self, text="Job:").grid(row=row + 2, column=0, sticky="e", **pad)
        self.job_var = tk.StringVar(value=existing_hero["char_job"] if existing_hero else "")
        tk.Entry(self, textvariable=self.job_var, width=30).grid(
            row=row + 2, column=1, columnspan=2, sticky="w", **pad)

        # --- Dungeon: Nest ---
        nest_frame = tk.LabelFrame(self, text="Nest")
        nest_frame.grid(row=row + 3, column=0, columnspan=3, sticky="we", padx=8, pady=(10, 4))
        self.nest_vars = {}
        for key, label in NEST_LABELS:
            var = tk.BooleanVar(value=existing_dungeon.get("nest", {}).get(key, False))
            tk.Checkbutton(nest_frame, text=label, variable=var).pack(side="left", padx=6, pady=4)
            self.nest_vars[key] = var

        # --- Dungeon: Dragon Fellowship ---
        dragon_frame = tk.LabelFrame(self, text="Dragon Fellowship")
        dragon_frame.grid(row=row + 4, column=0, columnspan=3, sticky="we", padx=8, pady=4)
        self.dragon_vars = {}
        for key, label in DRAGON_LABELS:
            var = tk.BooleanVar(value=existing_dungeon.get("dragon_fellowship", {}).get(key, False))
            tk.Checkbutton(dragon_frame, text=label, variable=var).pack(side="left", padx=6, pady=4)
            self.dragon_vars[key] = var

        # --- Tombol ---
        btn_frame = tk.Frame(self)
        btn_frame.grid(row=row + 5, column=0, columnspan=3, pady=12)
        tk.Button(btn_frame, text="Simpan", width=12, command=self.on_save).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Batal", width=12, command=self.destroy).pack(side="left", padx=6)

    def on_save(self):
        name = self.name_var.get().strip()
        job = self.job_var.get().strip()
        if not name:
            messagebox.showerror("Error", "Nama karakter tidak boleh kosong.", parent=self)
            return
        try:
            lvl = int(self.lvl_var.get())
        except ValueError:
            messagebox.showerror("Error", "Level harus berupa angka.", parent=self)
            return

        dungeon = {
            "nest": {key: var.get() for key, var in self.nest_vars.items()},
            "dragon_fellowship": {key: var.get() for key, var in self.dragon_vars.items()},
        }

        if self.hero_index is None:
            self.account_manager.add_hero(self.account_index, name, lvl, job, dungeon)
        else:
            self.account_manager.update_hero(
                self.account_index, self.hero_index, name, lvl, job, dungeon)

        self.result = True
        self.destroy()


# ---------------------------------------------------------------------------
# Jendela utama aplikasi
# ---------------------------------------------------------------------------
class MainWindow(tk.Tk):
    def __init__(self, config_manager: ConfigManager, account_manager: AccountManager):
        super().__init__()
        self.config_manager = config_manager
        self.account_manager = account_manager

        self.title("Game Account Tracker")
        self.geometry("1060x520")

        self.build_menu()
        self.build_widgets()
        self.refresh_table()

    def build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Ganti Master Password", command=self.change_master_password)
        file_menu.add_separator()
        file_menu.add_command(label="Keluar", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)
        self.config(menu=menubar)

    def build_widgets(self):
        toolbar = tk.Frame(self)
        toolbar.pack(fill="x", padx=8, pady=(8, 4))

        tk.Button(toolbar, text="Tambah Akun", command=self.add_account).pack(side="left", padx=4)
        tk.Button(toolbar, text="Edit Akun", command=self.edit_account).pack(side="left", padx=4)
        tk.Button(toolbar, text="Hapus Akun", command=self.delete_account).pack(side="left", padx=4)

        # Separator visual
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8, pady=2)

        tk.Button(toolbar, text="Tambah Hero", command=self.add_hero).pack(side="left", padx=4)
        tk.Button(toolbar, text="Edit Hero", command=self.edit_hero).pack(side="left", padx=4)
        tk.Button(toolbar, text="Hapus Hero", command=self.delete_hero).pack(side="left", padx=4)

        # Separator visual
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8, pady=2)

        tk.Button(toolbar, text="Lihat Password", command=self.view_password).pack(side="left", padx=4)
        tk.Button(toolbar, text="Refresh", command=self.refresh_table).pack(side="left", padx=4)

        # --- Sort bar (checkbox-based) ---
        sort_bar = tk.Frame(self)
        sort_bar.pack(fill="x", padx=8, pady=(0, 4))

        tk.Label(sort_bar, text="Urutkan:").pack(side="left", padx=(0, 4))

        self.sort_name_var = tk.BooleanVar(value=False)
        tk.Checkbutton(sort_bar, text="Nama A-Z", variable=self.sort_name_var,
                        command=self.refresh_table).pack(side="left", padx=4)

        self.sort_level_var = tk.BooleanVar(value=False)
        tk.Checkbutton(sort_bar, text="Level ↓", variable=self.sort_level_var,
                        command=self.refresh_table).pack(side="left", padx=4)

        self.sort_job_var = tk.BooleanVar(value=False)
        tk.Checkbutton(sort_bar, text="Job A-Z", variable=self.sort_job_var,
                        command=self.refresh_table).pack(side="left", padx=4)

        ttk.Separator(sort_bar, orient="vertical").pack(side="left", fill="y", padx=8, pady=2)

        tk.Label(sort_bar, text="Belum clear ↑ :").pack(side="left", padx=(0, 4))

        # Checkbox per dungeon — centang = yang belum selesai naik ke atas
        self.sort_dungeon_vars: dict[str, tk.BooleanVar] = {}
        all_dungeon_labels = [
            ("nest", "PKN_HC", "PKN HC"),
            ("nest", "TKN_HC", "TKN HC"),
            ("nest", "Guardian", "Guardian"),
            ("dragon_fellowship", "Dragon_Expedition_Lv60", "DF Lv.60"),
            ("dragon_fellowship", "Dragon_Expedition_Lv70", "DF Lv.70"),
        ]
        for category, key, label in all_dungeon_labels:
            var = tk.BooleanVar(value=False)
            full_key = f"{category}.{key}"
            tk.Checkbutton(sort_bar, text=label, variable=var,
                            command=self.refresh_table).pack(side="left", padx=3)
            self.sort_dungeon_vars[full_key] = var

        # Simpan referensi untuk dipakai di _build_sort_key
        self._all_dungeon_labels = all_dungeon_labels

        # --- Tabel ---
        columns = ("char_id", "char_name", "char_lvl", "char_job", "char_dungeon_info")
        headers = {
            "char_id": "Char ID",
            "char_name": "Nama Hero",
            "char_lvl": "Level",
            "char_job": "Job",
            "char_dungeon_info": "Info Dungeon",
        }
        widths = {
            "char_id": 100,
            "char_name": 130,
            "char_lvl": 60,
            "char_job": 110,
            "char_dungeon_info": 560,
        }

        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")

        # Scrollbar
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0, 8), pady=(0, 8))
        self.tree.pack(fill="both", expand=True, padx=(8, 0), pady=(0, 8))

        self.tree.bind("<Double-1>", lambda e: self.edit_hero())

    # --- helpers untuk menerjemahkan baris tabel ke (acc_idx, hero_idx) --------
    def _build_row_map(self):
        """Bangun mapping iid → (account_index, hero_index).
        Dipanggil setiap refresh_table."""
        self._row_map: dict[str, tuple[int, int]] = {}

    def _get_selected_ids(self) -> tuple[int, int] | None:
        """Kembalikan (account_index, hero_index) dari baris yang dipilih."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Pilih salah satu baris di tabel terlebih dahulu.")
            return None
        return self._row_map.get(sel[0])

    def _get_selected_account_index(self) -> int | None:
        """Kembalikan account_index dari baris yang dipilih (hero apapun)."""
        ids = self._get_selected_ids()
        if ids is None:
            return None
        return ids[0]

    # --- sorting logic --------------------------------------------------------
    def _build_sort_key(self, hero: dict) -> tuple:
        """Bangun sort key untuk satu hero berdasarkan checkbox yang aktif.

        Sort priority:
        1. Dungeon incomplete count (yang belum clear naik ke atas)
        2. Nama A-Z
        3. Level High→Low
        4. Job A-Z
        """
        dungeon = hero.get("dungeon", {})

        # Hitung jumlah dungeon yang di-centang DAN belum selesai
        # Semakin banyak yang belum clear → nilai makin kecil → naik ke atas
        incomplete_count = 0
        active_dungeon_checks = 0
        for category, key, _label in self._all_dungeon_labels:
            full_key = f"{category}.{key}"
            if self.sort_dungeon_vars.get(full_key, tk.BooleanVar()).get():
                active_dungeon_checks += 1
                cleared = dungeon.get(category, {}).get(key, False)
                if not cleared:
                    incomplete_count += 1

        # Sort key: belum clear lebih banyak → lebih kecil (naik ke atas)
        # Kita gunakan negatif supaya descending
        dungeon_priority = -incomplete_count if active_dungeon_checks > 0 else 0

        # Nama A-Z (case-insensitive)
        name_key = hero.get("char_name", "").lower() if self.sort_name_var.get() else ""

        # Level High→Low (negatif supaya descending)
        level_key = -hero.get("char_lvl", 0) if self.sort_level_var.get() else 0

        # Job A-Z (case-insensitive)
        job_key = hero.get("char_job", "").lower() if self.sort_job_var.get() else ""

        return (dungeon_priority, name_key, level_key, job_key)

    def _any_sort_active(self) -> bool:
        """Cek apakah ada checkbox sort yang aktif."""
        if self.sort_name_var.get() or self.sort_level_var.get() or self.sort_job_var.get():
            return True
        return any(var.get() for var in self.sort_dungeon_vars.values())

    # --- refresh tabel --------------------------------------------------------
    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        self._build_row_map()

        # Kumpulkan semua hero beserta indeks aslinya
        all_heroes: list[tuple[int, int, dict, dict]] = []
        for acc_idx, acc in enumerate(self.account_manager.accounts):
            for hero_idx, hero in enumerate(acc["characters"]):
                all_heroes.append((acc_idx, hero_idx, hero, acc))

        # Urutkan kalau ada sort yang aktif
        if hasattr(self, "sort_name_var") and self._any_sort_active():
            all_heroes.sort(key=lambda x: self._build_sort_key(x[2]))

        # Masukkan ke tabel
        row_id = 0
        seen_accounts: set[int] = set()
        for acc_idx, hero_idx, hero, acc in all_heroes:
            iid = str(row_id)
            summary = AccountManager.dungeon_summary(hero["dungeon"])
            # Tampilkan char_id hanya pada kemunculan pertama akun
            if acc_idx not in seen_accounts:
                display_id = acc["char_id"]
                seen_accounts.add(acc_idx)
            else:
                display_id = ""
            self.tree.insert("", "end", iid=iid, values=(
                display_id, hero["char_name"], hero["char_lvl"],
                hero["char_job"], summary
            ))
            self._row_map[iid] = (acc_idx, hero_idx)
            row_id += 1

    # --- akun CRUD ------------------------------------------------------------
    def add_account(self):
        dialog = AccountDialog(self, self.account_manager)
        self.wait_window(dialog)
        if dialog.result:
            self.refresh_table()

    def edit_account(self):
        acc_idx = self._get_selected_account_index()
        if acc_idx is None:
            return
        dialog = AccountDialog(self, self.account_manager, index=acc_idx)
        self.wait_window(dialog)
        if dialog.result:
            self.refresh_table()

    def delete_account(self):
        acc_idx = self._get_selected_account_index()
        if acc_idx is None:
            return
        acc = self.account_manager.accounts[acc_idx]
        hero_count = len(acc["characters"])
        if messagebox.askyesno(
            "Konfirmasi",
            f"Hapus akun '{acc['char_id']}' beserta {hero_count} hero di dalamnya?"
        ):
            self.account_manager.delete_account(acc_idx)
            self.refresh_table()

    # --- hero CRUD ------------------------------------------------------------
    def add_hero(self):
        acc_idx = self._get_selected_account_index()
        if acc_idx is None:
            return
        dialog = HeroDialog(self, self.account_manager, acc_idx)
        self.wait_window(dialog)
        if dialog.result:
            self.refresh_table()

    def edit_hero(self):
        ids = self._get_selected_ids()
        if ids is None:
            return
        acc_idx, hero_idx = ids
        dialog = HeroDialog(self, self.account_manager, acc_idx, hero_index=hero_idx)
        self.wait_window(dialog)
        if dialog.result:
            self.refresh_table()

    def delete_hero(self):
        ids = self._get_selected_ids()
        if ids is None:
            return
        acc_idx, hero_idx = ids
        acc = self.account_manager.accounts[acc_idx]
        hero = acc["characters"][hero_idx]
        if len(acc["characters"]) == 1:
            msg = (f"Ini adalah hero terakhir di akun '{acc['char_id']}'.\n"
                   f"Menghapusnya akan menghapus seluruh akun.\n\nLanjutkan?")
        else:
            msg = f"Hapus hero '{hero['char_name']}' dari akun '{acc['char_id']}'?"
        if messagebox.askyesno("Konfirmasi", msg):
            self.account_manager.delete_hero(acc_idx, hero_idx)
            self.refresh_table()

    # --- lainnya --------------------------------------------------------------
    def view_password(self):
        acc_idx = self._get_selected_account_index()
        if acc_idx is None:
            return
        acc = self.account_manager.accounts[acc_idx]
        pw = self.account_manager.decrypt_password(acc["password_enc"])
        messagebox.showinfo("Password Akun", f"Character ID: {acc['char_id']}\nPassword: {pw}")

    def change_master_password(self):
        old_pw = simpledialog.askstring("Verifikasi", "Masukkan master password saat ini:", show="*", parent=self)
        if old_pw is None:
            return
        if not self.config_manager.verify_password(old_pw):
            messagebox.showerror("Error", "Password lama salah.")
            return
        new_pw = simpledialog.askstring("Password Baru", "Masukkan master password baru:", show="*", parent=self)
        if not new_pw:
            return
        confirm_pw = simpledialog.askstring("Konfirmasi", "Ulangi master password baru:", show="*", parent=self)
        if new_pw != confirm_pw:
            messagebox.showerror("Error", "Konfirmasi password tidak cocok.")
            return

        # Dekripsi semua password akun dengan kunci lama, ganti salt enkripsi,
        # lalu enkripsi ulang semua dengan kunci baru.
        old_fernet = self.account_manager.fernet
        plain_passwords = [old_fernet.decrypt(acc["password_enc"].encode()).decode()
                            for acc in self.account_manager.accounts]

        new_enc_salt = secrets.token_bytes(16)
        self.config_manager.data["enc_salt"] = base64.b64encode(new_enc_salt).decode()
        new_key = derive_key(new_pw, new_enc_salt)
        new_fernet = Fernet(new_key)

        for acc, plain in zip(self.account_manager.accounts, plain_passwords):
            acc["password_enc"] = new_fernet.encrypt(plain.encode()).decode()

        self.account_manager.fernet = new_fernet
        self.account_manager.save()
        self.config_manager.change_password(new_pw)

        messagebox.showinfo("Berhasil", "Master password berhasil diganti.")


# ---------------------------------------------------------------------------
# Alur login / setup awal
# ---------------------------------------------------------------------------
def run_setup_flow(config_manager: ConfigManager) -> str:
    """Tampilkan dialog untuk membuat master password (hanya sekali)."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "Setup Awal",
        "Ini pertama kalinya kamu menjalankan aplikasi.\n"
        "Buat master password untuk mengamankan data akun kamu."
    )
    while True:
        pw1 = simpledialog.askstring("Buat Master Password", "Master password baru:", show="*")
        if pw1 is None:
            root.destroy()
            raise SystemExit
        if len(pw1) < 4:
            messagebox.showerror("Error", "Password minimal 4 karakter.")
            continue
        pw2 = simpledialog.askstring("Konfirmasi", "Ulangi master password:", show="*")
        if pw1 == pw2:
            break
        messagebox.showerror("Error", "Password tidak cocok, coba lagi.")
    config_manager.setup_master_password(pw1)
    root.destroy()
    return pw1


def run_login_flow(config_manager: ConfigManager) -> str:
    """Tampilkan dialog login, kembalikan master password jika benar."""
    root = tk.Tk()
    root.withdraw()
    attempts = 0
    while attempts < 5:
        pw = simpledialog.askstring("Login", "Masukkan master password:", show="*")
        if pw is None:
            root.destroy()
            raise SystemExit
        if config_manager.verify_password(pw):
            root.destroy()
            return pw
        attempts += 1
        messagebox.showerror("Error", f"Password salah. Percobaan {attempts}/5.")
    messagebox.showerror("Error", "Terlalu banyak percobaan gagal. Aplikasi ditutup.")
    root.destroy()
    raise SystemExit


def main():
    config_manager = ConfigManager()

    if not config_manager.is_configured():
        master_password = run_setup_flow(config_manager)
    else:
        master_password = run_login_flow(config_manager)

    enc_key = config_manager.get_enc_key(master_password)
    fernet = Fernet(enc_key)
    account_manager = AccountManager(fernet)

    app = MainWindow(config_manager, account_manager)
    app.mainloop()


if __name__ == "__main__":
    main()
