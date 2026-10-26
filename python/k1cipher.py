#!/usr/bin/env python3
"""
K1 Cipher – Python / desktop version
Developer: Keyvan Adili (کیوان عدیلی)

Same screen, same colors and the SAME encrypted format as the Android app, so text and
.k1c files can be exchanged between the two in both directions.

  KDF   : Argon2id v1.3, 64 MiB, 3 passes, random 16-byte salt per message
  Cipher: AES-256-GCM, random 12-byte nonce, header authenticated as AAD
  Layout: "K1C" | ver(1) | memKiB(4) | iter(1) | par(1) | salt(16) | nonce(12) | ciphertext+tag

Run:  pip install -r requirements.txt   then   python k1cipher.py [file.k1c]
"""
import base64
import binascii
import os
import queue
import struct
import sys
import threading
import tkinter as tk
from tkinter import filedialog
from tkinter import font as tkfont

import segno
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_VERSION = "1.2"

# ----------------------------------------------------------------------------------------
#  Crypto
# ----------------------------------------------------------------------------------------

MAGIC = b"K1C"
VERSION = 1
SALT_LEN, NONCE_LEN, KEY_LEN, TAG_LEN = 16, 12, 32, 16
HEADER_LEN = 3 + 1 + 4 + 1 + 1 + SALT_LEN + NONCE_LEN  # 38
PAD_BLOCK = 64
MEM_KIB, ITERATIONS, PARALLELISM = 65_536, 3, 1
MEM_RANGE, ITER_RANGE, PAR_RANGE = range(8_192, 262_145), range(1, 11), range(1, 5)
MAX_PLAIN_CHARS = 1_000_000
MAX_FILE_BYTES = 8 * 1024 * 1024


class WrongPassword(Exception):
    pass


class InvalidFormat(Exception):
    pass


def _derive_key(password: bytes, salt: bytes, mem: int, it: int, par: int) -> bytes:
    return hash_secret_raw(
        secret=password, salt=salt, time_cost=it, memory_cost=mem,
        parallelism=par, hash_len=KEY_LEN, type=Type.ID, version=19,
    )


def _pad(b: bytes) -> bytes:
    total = ((len(b) + 1 + PAD_BLOCK - 1) // PAD_BLOCK) * PAD_BLOCK
    return b + b"\x80" + b"\x00" * (total - len(b) - 1)


def _unpad(b: bytes) -> bytes:
    stripped = b.rstrip(b"\x00")
    if not stripped.endswith(b"\x80"):
        raise InvalidFormat()
    return stripped[:-1]


def is_container(b: bytes) -> bool:
    return len(b) >= HEADER_LEN + TAG_LEN + 1 and b[:3] == MAGIC and b[3] == VERSION


def encrypt(plain: str, password: bytes) -> bytes:
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    header = MAGIC + bytes([VERSION]) + struct.pack(">IBB", MEM_KIB, ITERATIONS, PARALLELISM) + salt + nonce
    key = _derive_key(password, salt, MEM_KIB, ITERATIONS, PARALLELISM)
    return header + AESGCM(key).encrypt(nonce, _pad(plain.encode("utf-8")), header)


def decrypt(data: bytes, password: bytes) -> str:
    if not is_container(data):
        raise InvalidFormat()
    mem, it, par = struct.unpack(">IBB", data[4:10])
    if mem not in MEM_RANGE or it not in ITER_RANGE or par not in PAR_RANGE:
        raise InvalidFormat()
    salt, nonce = data[10:26], data[26:38]
    header, body = data[:HEADER_LEN], data[HEADER_LEN:]
    key = _derive_key(password, salt, mem, it, par)
    try:
        padded = AESGCM(key).decrypt(nonce, body, header)
    except InvalidTag:
        raise WrongPassword() from None
    try:
        return _unpad(padded).decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidFormat() from None


def to_token(container: bytes) -> str:
    return base64.urlsafe_b64encode(container).rstrip(b"=").decode("ascii")


def from_token(text: str):
    """Container bytes if `text` is a valid K1 Cipher token, else None."""
    s = "".join(ch for ch in text if not ch.isspace() and ch != "=")
    if not s:
        return None
    try:
        data = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if is_container(data) else None


# ----------------------------------------------------------------------------------------
#  UI  (colors / sizes measured from the reference design; units are "dp" of a 360-wide phone)
# ----------------------------------------------------------------------------------------

BG, BOX = "#5E5E5E", "#535252"
BLUE, TEAL, YELLOW = "#0096FF", "#00FFCC", "#FFFF00"
SUBTITLE = FOOTER = "#C2C2C2"
DISABLED_TEXT = "#414141"
CLEAR_ACTIVE = "#FF5A5A"
INPUT_TEXT = "#EAEAEA"

S = float(os.environ.get("K1_SCALE", "1.1"))  # window scale


def d(v: float) -> int:
    return int(round(v * S))


def center_window(root: tk.Tk):
    root.update_idletasks()
    x = max(0, (root.winfo_screenwidth() - root.winfo_width()) // 2)
    y = max(0, (root.winfo_screenheight() - root.winfo_height()) // 2)
    root.geometry(f"+{x}+{y}")


def pick_font(root, names, default):
    fams = set(tkfont.families(root))
    return next((n for n in names if n in fams), default)


def rrect(c, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


class TileButton:
    SIZE = 85

    def __init__(self, app, x, y, text, color, command):
        c, w, size = app.canvas, d(3.3), d(self.SIZE)
        self.c, self.color, self.command, self.enabled = c, color, command, True
        self.rect = rrect(c, x + w / 2, y + w / 2, x + size - w / 2, y + size - w / 2, d(15),
                          fill=BG, outline=color, width=w)
        fsize = d(14)
        font = tkfont.Font(family=app.ui_font, size=-fsize, weight="bold")
        while font.measure(text) > size - 2 * w - d(8) and fsize > 8:  # label must fit on one line
            fsize -= 1
            font.config(size=-fsize)
        self.label = c.create_text(x + size / 2, y + size / 2, text=text, fill=color, font=font)
        for item in (self.rect, self.label):
            c.tag_bind(item, "<Button-1>", self._click)
            c.tag_bind(item, "<Enter>", lambda e: c.config(cursor="hand2" if self.enabled else ""))
            c.tag_bind(item, "<Leave>", lambda e: c.config(cursor=""))

    def _click(self, _event):
        if self.enabled:
            self.command()

    def set_enabled(self, enabled: bool):
        if enabled == self.enabled:
            return
        self.enabled = enabled
        self.c.itemconfigure(self.rect, outline=self.color if enabled else BOX)
        self.c.itemconfigure(self.label, fill=self.color if enabled else DISABLED_TEXT)


def ask_password(root, confirm: bool, text_font):
    """Modal password dialog. Returns the password (str) or None if cancelled."""
    dlg = tk.Toplevel(root)
    dlg.title("Set password" if confirm else "Enter password")
    dlg.configure(bg=BOX, padx=18, pady=14)
    dlg.transient(root)
    dlg.resizable(False, False)
    out = {"pw": None}
    v1, v2, show = tk.StringVar(), tk.StringVar(), tk.BooleanVar(value=False)

    def entry(var):
        return tk.Entry(dlg, textvariable=var, show="•", width=30, bg=BG, fg=INPUT_TEXT,
                        insertbackground=BLUE, relief="flat", font=(text_font, 12),
                        highlightthickness=2, highlightbackground=BG, highlightcolor=BLUE)

    tk.Label(dlg, text="Set password" if confirm else "Enter password", bg=BOX, fg=BLUE,
             font=(text_font, 14, "bold")).pack(anchor="w")
    e1 = entry(v1)
    e1.pack(fill="x", pady=(10, 4), ipady=4)
    e2 = None
    if confirm:
        tk.Label(dlg, text="Repeat password", bg=BOX, fg=SUBTITLE, font=(text_font, 9)).pack(anchor="w")
        e2 = entry(v2)
        e2.pack(fill="x", pady=(2, 4), ipady=4)
    info = tk.Label(dlg, text="", bg=BOX, fg=CLEAR_ACTIVE, font=(text_font, 9), anchor="w")
    info.pack(fill="x")

    def toggle():
        ch = "" if show.get() else "•"
        e1.config(show=ch)
        if e2:
            e2.config(show=ch)

    tk.Checkbutton(dlg, text="Show", variable=show, command=toggle, bg=BOX, fg=SUBTITLE,
                   selectcolor=BG, activebackground=BOX, activeforeground=SUBTITLE,
                   font=(text_font, 9)).pack(anchor="w")

    row = tk.Frame(dlg, bg=BOX)
    row.pack(fill="x", pady=(8, 0))
    ok = tk.Button(row, text="ENCRYPT" if confirm else "DECRYPT", relief="flat", bg=BG, fg=BLUE,
                   activebackground=BG, activeforeground=BLUE, font=(text_font, 10, "bold"), padx=10)
    ok.pack(side="right")
    cancel = tk.Button(row, text="CANCEL", relief="flat", bg=BG, fg=SUBTITLE, activebackground=BG,
                       activeforeground=SUBTITLE, font=(text_font, 10, "bold"), padx=10,
                       command=dlg.destroy)
    cancel.pack(side="right", padx=8)

    def validate(*_):
        p1, p2 = v1.get(), v2.get()
        if confirm:
            if p1 and len(p1) < 8:
                info.config(text="At least 8 characters – a long passphrase is best")
            elif p2 and p1 != p2:
                info.config(text="Passwords do not match")
            else:
                info.config(text="")
            valid = len(p1) >= 8 and p1 == p2
        else:
            valid = bool(p1)
        ok.config(state="normal" if valid else "disabled")
        return valid

    def submit(*_):
        if validate():
            out["pw"] = v1.get()
            dlg.destroy()

    ok.config(command=submit)
    v1.trace_add("write", validate)
    v2.trace_add("write", validate)
    dlg.bind("<Return>", submit)
    dlg.bind("<Escape>", lambda e: dlg.destroy())
    validate()

    dlg.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() - dlg.winfo_width()) // 2
    y = root.winfo_rooty() + max(40, (root.winfo_height() - dlg.winfo_height()) // 3)
    dlg.geometry(f"+{x}+{y}")
    dlg.grab_set()
    e1.focus_set()
    root.wait_window(dlg)
    return out["pw"]


def show_qr(root, token: str, text_font) -> bool:
    """Show the encrypted text as a QR code (so a phone can scan it). False if it is too long."""
    qr = None
    for level in ("M", "L"):  # prefer better error correction, fall back to bigger capacity
        try:
            qr = segno.make(token, error=level, micro=False)
            break
        except segno.DataOverflowError:
            continue
    if qr is None:
        return False

    matrix = [list(row) for row in qr.matrix]
    n, quiet = len(matrix), 4
    mod = max(2, min(8, 440 // (n + 2 * quiet)))
    size = (n + 2 * quiet) * mod

    dlg = tk.Toplevel(root)
    dlg.title("K1 Cipher – QR code")
    dlg.configure(bg=BOX, padx=18, pady=14)
    dlg.transient(root)
    dlg.resizable(False, False)
    tk.Label(dlg, text="Scan to receive the encrypted text", bg=BOX, fg=BLUE,
             font=(text_font, 12, "bold")).pack(anchor="w", pady=(0, 8))

    c = tk.Canvas(dlg, width=size, height=size, bg="white", highlightthickness=0)
    c.pack()
    for y, row in enumerate(matrix):  # draw horizontal runs of dark modules
        x = 0
        while x < n:
            if row[x]:
                start = x
                while x < n and row[x]:
                    x += 1
                c.create_rectangle((quiet + start) * mod, (quiet + y) * mod,
                                   (quiet + x) * mod, (quiet + y + 1) * mod, fill="black", width=0)
            else:
                x += 1

    note = tk.Label(dlg, text="", bg=BOX, fg=TEAL, font=(text_font, 9))
    note.pack(pady=(6, 0))

    def copy_text():
        root.clipboard_clear()
        root.clipboard_append(token)
        root.update()
        note.config(text="Text copied")

    def save_png():
        path = filedialog.asksaveasfilename(
            parent=dlg, defaultextension=".png", initialfile="K1Cipher-QR.png",
            filetypes=[("PNG image", "*.png")])
        if path:
            try:
                qr.save(path, scale=10, border=4)
                note.config(text="Image saved")
            except OSError:
                note.config(text="Could not save the image")

    row = tk.Frame(dlg, bg=BOX)
    row.pack(fill="x", pady=(8, 0))
    for text, color, cmd in (("CLOSE", SUBTITLE, dlg.destroy), ("SAVE PNG", BLUE, save_png),
                             ("COPY TEXT", TEAL, copy_text)):
        tk.Button(row, text=text, command=cmd, relief="flat", bg=BG, fg=color, activebackground=BG,
                  activeforeground=color, font=(text_font, 10, "bold"), padx=10).pack(side="right", padx=(8, 0))
    dlg.bind("<Escape>", lambda e: dlg.destroy())

    dlg.update_idletasks()
    x = root.winfo_rootx() + max(0, (root.winfo_width() - dlg.winfo_width()) // 2)
    y = root.winfo_rooty() + 30
    dlg.geometry(f"+{x}+{y}")
    dlg.focus_set()
    return True


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("K1 Cipher")
        root.configure(bg=BG)
        root.resizable(False, False)

        self.ui_font = pick_font(root, ["Myriad Pro", "Open Sans", "Segoe UI", "Noto Sans", "DejaVu Sans"], "Helvetica")
        self.text_font = pick_font(root, ["Vazirmatn", "Vazir", "Tahoma", "Segoe UI", "Noto Sans", "DejaVu Sans"], "Helvetica")

        self.busy = False
        self.results = queue.Queue()
        self._toast_after = None

        W, H = d(360), d(640)
        self.canvas = c = tk.Canvas(root, width=W, height=H, bg=BG, highlightthickness=0)
        c.pack()

        # Title (shrinks if the chosen font is wider than the window)
        size = d(56)
        title_font = tkfont.Font(family=self.ui_font, size=-size, weight="bold")
        while title_font.measure("K1 Cipher") > W - d(60) and size > 20:
            size -= 1
            title_font.config(size=-size)
        c.create_text(W / 2, d(8), text="K1 Cipher", fill=BLUE, font=title_font, anchor="n")
        c.create_text(W / 2, d(74), text="Encrypt and decrypt your text and share\nto other app or save in file",
                      fill=SUBTITLE, font=(self.ui_font, -d(13)), justify="center", anchor="n")

        self.plain, self.plain_hint = self._field(d(132), "Normal or Decrypt Text", BLUE)
        self.enc, self.enc_hint = self._field(d(261), "Encrypt text", TEAL)

        xs = [d(33 + i * (TileButton.SIZE + 19.5)) for i in range(3)]
        y1, y2 = d(391), d(486)
        self.btn_encrypt = TileButton(self, xs[0], y1, "ENCRYPT", TEAL, self.request_encrypt)
        self.btn_decrypt = TileButton(self, xs[1], y1, "DECRYPT", BLUE, self.request_decrypt)
        self.btn_share = TileButton(self, xs[2], y1, "Share", YELLOW, self.share)
        self.btn_save = TileButton(self, xs[0], y2, "SAVE", BLUE, self.save)
        self.btn_read = TileButton(self, xs[1], y2, "READ FILE", BLUE, self.read_file)
        self.btn_clear = TileButton(self, xs[2], y2, "CLEAR", CLEAR_ACTIVE, self.clear_all)
        self.btn_clear.set_enabled(False)
        self.buttons = [self.btn_encrypt, self.btn_decrypt, self.btn_share,
                        self.btn_save, self.btn_read, self.btn_clear]

        c.create_text(W / 2, d(585), text=f"Developer: Keyvan Adili\nversion: {APP_VERSION}",
                      fill=FOOTER, font=(self.ui_font, -d(10)), justify="center", anchor="n")
        self.toast_item = c.create_text(W / 2, d(622), text="", fill=TEAL, state="hidden",
                                        font=(self.ui_font, -d(12), "bold"), anchor="n")

        self._tick()
        self._pump()

    # ---- widgets ----

    def _field(self, y, hint, color):
        c = self.canvas
        x1, x2, h, w = d(30), d(330), d(122), d(1.7)
        rrect(c, x1 + w / 2, y + w / 2, x2 - w / 2, y + h - w / 2, d(15), fill=BOX, outline=color, width=w)
        tx, ty, tw, th = x1 + d(15), y + d(12), (x2 - x1) - d(30), h - d(24)
        text = tk.Text(c, bg=BOX, fg=INPUT_TEXT, insertbackground=color, relief="flat", bd=0,
                       highlightthickness=0, wrap="word", undo=True, padx=0, pady=0,
                       font=(self.text_font, -d(15)), selectbackground=color, selectforeground=BG)
        c.create_window(tx, ty, window=text, anchor="nw", width=tw, height=th)
        label = tk.Label(c, text=hint, bg=BOX, fg=color, font=(self.text_font, -d(15)), anchor="nw")
        win = c.create_window(tx, ty, window=label, anchor="nw")
        label.bind("<Button-1>", lambda e: text.focus_set())
        text.bind("<Control-a>", lambda e: (text.tag_add("sel", "1.0", "end-1c"), "break")[1])
        return text, win

    @staticmethod
    def _get(w) -> str:
        return w.get("1.0", "end-1c")

    @staticmethod
    def _set(w, s: str):
        w.delete("1.0", "end")
        w.insert("1.0", s)

    def _tick(self):
        c = self.canvas
        c.itemconfigure(self.plain_hint, state="hidden" if self._get(self.plain) else "normal")
        c.itemconfigure(self.enc_hint, state="hidden" if self._get(self.enc) else "normal")
        has = bool(self._get(self.plain) or self._get(self.enc))
        self.btn_clear.set_enabled(has and not self.busy)
        self.root.after(150, self._tick)

    def toast(self, msg: str):
        c = self.canvas
        if self._toast_after:
            self.root.after_cancel(self._toast_after)
        c.itemconfigure(self.toast_item, text=msg, state="normal")
        self._toast_after = self.root.after(2600, lambda: c.itemconfigure(self.toast_item, state="hidden"))

    def _set_busy(self, busy: bool):
        self.busy = busy
        for b in self.buttons[:-1]:
            b.set_enabled(not busy)
        self.root.config(cursor="watch" if busy else "")
        if busy:
            self.toast("Working…")

    # ---- background work (Argon2 takes ~1 s, keep the UI alive) ----

    def _run(self, fn, on_ok):
        self._set_busy(True)

        def work():
            try:
                res = ("ok", fn())
            except WrongPassword:
                res = ("err", "Wrong password, or the text was modified")
            except InvalidFormat:
                res = ("err", "This is not valid K1 Cipher text")
            except Exception:
                res = ("err", "Operation failed")
            self.results.put((on_ok, res))

        threading.Thread(target=work, daemon=True).start()

    def _pump(self):
        try:
            while True:
                on_ok, (kind, value) = self.results.get_nowait()
                self._set_busy(False)
                if kind == "ok":
                    on_ok(value)
                    self.toast("Done")
                else:
                    self.toast(value)
        except queue.Empty:
            pass
        self.root.after(50, self._pump)

    # ---- actions ----

    def _decrypt_source(self):
        for t in (self._get(self.enc), self._get(self.plain)):
            if t.strip() and from_token(t) is not None:
                return t
        return None

    def request_encrypt(self):
        text = self._get(self.plain)
        if not text:
            return self.toast("Type or paste some text first")
        if len(text) > MAX_PLAIN_CHARS:
            return self.toast("Text is too long")
        pw = ask_password(self.root, True, self.text_font)
        if pw is None:
            return
        pwb = pw.encode("utf-8")
        self._run(lambda: to_token(encrypt(text, pwb)), lambda out: self._set(self.enc, out))

    def request_decrypt(self):
        src = self._decrypt_source()
        if src is None:
            return self.toast("Paste or load encrypted text first")
        pw = ask_password(self.root, False, self.text_font)
        if pw is None:
            return
        pwb = pw.encode("utf-8")

        def done(plain):
            self._set(self.enc, src)
            self._set(self.plain, plain)

        self._run(lambda: decrypt(from_token(src), pwb), done)

    def clear_all(self):
        self._set(self.plain, "")
        self._set(self.enc, "")

    def share(self):
        """Desktop has no share sheet: copy the encrypted text and show it as a QR code."""
        token = "".join(self._get(self.enc).split())
        if not token:
            return self.toast("Nothing to share – encrypt something first")
        self.root.clipboard_clear()
        self.root.clipboard_append(token)
        self.root.update()
        if show_qr(self.root, token, self.text_font):
            self.toast("Copied – or scan the QR code")
        else:
            self.toast("Copied – too long for a QR code")

    def save(self):
        data = from_token(self._get(self.enc))
        if data is None:
            return self.toast("Nothing to save – encrypt something first")
        path = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=".k1c", initialfile="K1Cipher.k1c",
            filetypes=[("K1 Cipher", "*.k1c"), ("All files", "*.*")])
        if not path:
            return
        tmp = path + ".tmp"
        try:  # write to a temp file, then atomically replace: never leaves a half-written file
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            self.toast("File saved")
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            self.toast("Could not save the file")

    def read_file(self):
        path = filedialog.askopenfilename(
            parent=self.root, filetypes=[("K1 Cipher", "*.k1c"), ("All files", "*.*")])
        if path:
            self.load_file(path)

    def load_file(self, path: str):
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_FILE_BYTES + 1)
        except OSError:
            return self.toast("Could not read the file")
        if len(data) > MAX_FILE_BYTES:
            return self.toast("File is too large")
        if is_container(data):
            token = to_token(data)
        else:
            text = data.decode("utf-8", errors="ignore")
            token = "".join(text.split()) if from_token(text) is not None else None
        if token is None:
            return self.toast("This is not a K1 Cipher file")
        self._set(self.enc, token)
        self.toast("File loaded – press DECRYPT")


def main():
    if sys.platform == "win32":
        try:  # crisp text on high-DPI screens
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    app = App(root)
    center_window(root)
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        root.after(100, lambda: app.load_file(sys.argv[1]))
    root.mainloop()


if __name__ == "__main__":
    main()
