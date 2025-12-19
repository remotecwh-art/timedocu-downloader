import os
import posixpath
import threading
import queue
from dataclasses import dataclass
from ftplib import FTP, FTP_TLS
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# =============================
# 고정 설정(로그인 화면에 노출 안 됨)
# =============================
HOST = "timedocu.co.kr"
PORT = 21
REMOTE_BASE_DIR = "/timedocu/tizstudio"   # NAS FTP 가상 루트 기준 경로
DEFAULT_LOCAL_DIR = os.path.abspath("./tizstudio_download")

# FTPS 옵션 노출 여부/기본값
SHOW_FTPS_OPTION = True
DEFAULT_USE_FTPS = False


# =============================
# FTP Client
# =============================
@dataclass
class RemoteItem:
    name: str
    is_dir: bool
    size: int | None = None
    modify: str | None = None


class FTPClient:
    def __init__(self):
        self.ftp = None
        self.use_ftps = False

    def connect(self, username: str, password: str, use_ftps: bool):
        self.close()
        self.use_ftps = use_ftps
        self.ftp = FTP_TLS() if use_ftps else FTP()
        self.ftp.connect(HOST, PORT, timeout=30)
        self.ftp.login(username, password)
        if use_ftps:
            self.ftp.prot_p()

    def close(self):
        try:
            if self.ftp:
                self.ftp.quit()
        except Exception:
            pass
        self.ftp = None

    def pwd(self) -> str:
        return self.ftp.pwd()

    def cwd(self, path: str):
        self.ftp.cwd(path)

    def _supports_mlsd(self) -> bool:
        try:
            list(self.ftp.mlsd("."))
            return True
        except Exception:
            return False

    def is_dir(self, path: str) -> bool:
        cur = self.ftp.pwd()
        try:
            self.ftp.cwd(path)
            self.ftp.cwd(cur)
            return True
        except Exception:
            return False

    def list_dir(self, remote_dir: str) -> list[RemoteItem]:
        items: list[RemoteItem] = []

        # Prefer MLSD (reliable type info)
        if self._supports_mlsd():
            try:
                for name, facts in self.ftp.mlsd(remote_dir):
                    if name in (".", ".."):
                        continue
                    t = (facts.get("type") or "").lower()
                    is_dir = (t == "dir")
                    size = None
                    if "size" in facts:
                        try:
                            size = int(facts["size"])
                        except Exception:
                            size = None
                    modify = facts.get("modify")
                    items.append(RemoteItem(name=name, is_dir=is_dir, size=size, modify=modify))
                items.sort(key=lambda x: (not x.is_dir, x.name.lower()))
                return items
            except Exception:
                pass

        # Fallback: NLST + CWD probe
        names = self.ftp.nlst(remote_dir)
        normalized = []
        for n in names:
            if n in (".", ".."):
                continue
            if n == remote_dir:
                continue
            if n.startswith(remote_dir.rstrip("/") + "/"):
                normalized.append(n)
            else:
                normalized.append(posixpath.join(remote_dir, n))

        for full_path in normalized:
            name = posixpath.basename(full_path.rstrip("/"))
            items.append(RemoteItem(name=name, is_dir=self.is_dir(full_path)))

        items.sort(key=lambda x: (not x.is_dir, x.name.lower()))
        return items

    def ensure_local_dir(self, path: str):
        if path and not os.path.exists(path):
            os.makedirs(path, exist_ok=True)

    def download_file(self, remote_file: str, local_file: str, log):
        self.ensure_local_dir(os.path.dirname(local_file))
        with open(local_file, "wb") as f:
            self.ftp.retrbinary(f"RETR {remote_file}", f.write)
        log(f"[OK ] FILE {remote_file} -> {local_file}")

    def download_dir_recursive(self, remote_dir: str, local_dir: str, log):
        self.ensure_local_dir(local_dir)
        children = self.list_dir(remote_dir)
        for ch in children:
            r = remote_dir.rstrip("/") + "/" + ch.name
            l = os.path.join(local_dir, ch.name)
            if ch.is_dir:
                log(f"[DIR] {r}")
                self.download_dir_recursive(r, l, log)
            else:
                log(f"[GET] {r}")
                self.download_file(r, l, log)


# =============================
# GUI
# =============================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FTP Downloader (GUI)")
        self.geometry("980x680")

        self.client = FTPClient()
        self.log_q = queue.Queue()

        self.login_frame = LoginFrame(self, self.on_login_success)
        self.browser_frame = None

        self.login_frame.pack(fill="both", expand=True)
        self.after(100, self._drain_log_queue)

    def on_login_success(self, cfg):
        if self.browser_frame:
            self.browser_frame.destroy()
        self.login_frame.pack_forget()
        self.browser_frame = BrowserFrame(self, self.client, cfg, self.on_logout, self.log_q)
        self.browser_frame.pack(fill="both", expand=True)

    def on_logout(self):
        try:
            self.client.close()
        except Exception:
            pass
        if self.browser_frame:
            self.browser_frame.pack_forget()
            self.browser_frame.destroy()
            self.browser_frame = None
        self.login_frame.pack(fill="both", expand=True)

    def _drain_log_queue(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                if self.browser_frame:
                    self.browser_frame.append_log(msg)
        except queue.Empty:
            pass
        self.after(100, self._drain_log_queue)


class LoginFrame(ttk.Frame):
    def __init__(self, master, on_success):
        super().__init__(master, padding=16)
        self.on_success = on_success

        self.var_user = tk.StringVar(value="")
        self.var_pass = tk.StringVar(value="")
        self.var_ftps = tk.BooleanVar(value=DEFAULT_USE_FTPS)
        self.var_local_dir = tk.StringVar(value=DEFAULT_LOCAL_DIR)

        title = ttk.Label(self, text="FTP 로그인", font=("Segoe UI", 16, "bold"))
        title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 12))

        ttk.Label(self, text="ID").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=6)
        ttk.Entry(self, textvariable=self.var_user, width=36).grid(row=1, column=1, sticky="w", pady=6)

        ttk.Label(self, text="Password").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=6)
        ttk.Entry(self, textvariable=self.var_pass, show="*", width=36).grid(row=2, column=1, sticky="w", pady=6)

        if SHOW_FTPS_OPTION:
            ttk.Checkbutton(self, text="FTPS(FTP over TLS) 사용", variable=self.var_ftps)\
                .grid(row=2, column=2, columnspan=2, sticky="w", padx=(18, 0), pady=6)

        ttk.Label(self, text="로컬 저장 폴더").grid(row=3, column=0, sticky="e", padx=(0, 8), pady=6)
        ttk.Entry(self, textvariable=self.var_local_dir, width=56).grid(row=3, column=1, columnspan=2, sticky="w", pady=6)
        ttk.Button(self, text="찾아보기", command=self.browse_local).grid(row=3, column=3, sticky="w", pady=6)

        ttk.Button(self, text="로그인", command=self.login, width=14).grid(row=4, column=1, sticky="w", pady=(14, 0))

        ttk.Label(
            self,
            text="※ 451 Cannot chroot 등 로그인 실패는 NAS FTP 루트/권한 설정 문제일 수 있습니다."
        ).grid(row=5, column=0, columnspan=4, sticky="w", pady=(14, 0))

        self.columnconfigure(1, weight=1)

    def browse_local(self):
        d = filedialog.askdirectory(initialdir=self.var_local_dir.get() or os.getcwd())
        if d:
            self.var_local_dir.set(d)

    def login(self):
        user = self.var_user.get().strip()
        pw = self.var_pass.get()
        use_ftps = bool(self.var_ftps.get()) if SHOW_FTPS_OPTION else DEFAULT_USE_FTPS
        local_dir = self.var_local_dir.get().strip()

        if not user:
            messagebox.showerror("입력 오류", "ID는 필수입니다.")
            return

        try:
            self.master.client.connect(user, pw, use_ftps)
            # 시작 경로 접근 확인(노출은 안 하지만 내부 검증)
            self.master.client.cwd(REMOTE_BASE_DIR)
            self.master.client.cwd("/")
        except Exception as e:
            messagebox.showerror("로그인 실패", f"{e}")
            try:
                self.master.client.close()
            except Exception:
                pass
            return

        cfg = {
            "user": user,
            "use_ftps": use_ftps,
            "remote_base": REMOTE_BASE_DIR,
            "local_dir": local_dir,
        }
        self.on_success(cfg)


class BrowserFrame(ttk.Frame):
    def __init__(self, master, client: FTPClient, cfg, on_logout, log_q: queue.Queue):
        super().__init__(master, padding=12)
        self.client = client
        self.cfg = cfg
        self.on_logout = on_logout
        self.log_q = log_q

        self.current_dir = cfg["remote_base"]

        # =========================
        # Top bar
        # =========================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 8))

        ttk.Button(top, text="로그아웃", command=self.on_logout).pack(side="left")
        ttk.Label(top, text="  ").pack(side="left")
        self.lbl_path = ttk.Label(top, text=f"원격 경로: {self.current_dir}")
        self.lbl_path.pack(side="left")

        ttk.Label(top, text="  ").pack(side="left")
        ttk.Button(top, text="새로고침", command=self.refresh).pack(side="left")

        ttk.Label(top, text="  ").pack(side="left")
        ttk.Button(top, text="상위 폴더", command=self.go_up).pack(side="left")

        # =========================
        # Controls
        # =========================
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=(0, 6))

        ttk.Button(controls, text="전체 선택", command=self.select_all).pack(side="left")
        ttk.Button(controls, text="선택 다운로드", command=self.download_selected).pack(side="left")
        ttk.Label(controls, text="  ").pack(side="left")
        ttk.Button(controls, text="선택 해제", command=self.clear_selection).pack(side="left")

        ttk.Label(controls, text="  로컬 저장: ").pack(side="left")
        self.lbl_local = ttk.Label(controls, text=self.cfg["local_dir"])
        self.lbl_local.pack(side="left")

        ttk.Label(controls, text="  ").pack(side="left")
        ttk.Button(controls, text="로컬 폴더 변경", command=self.change_local).pack(side="left")

        # =========================
        # Center: Treeview (list)
        # =========================
        center = ttk.Frame(self)
        center.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(
            center,
            columns=("name", "type", "size", "modify"),
            show="headings",
            selectmode="extended"  # Shift/Ctrl 다중 선택
        )
        self.tree.heading("name", text="이름")
        self.tree.heading("type", text="타입")
        self.tree.heading("size", text="크기")
        self.tree.heading("modify", text="수정시간")

        self.tree.column("name", width=520)
        self.tree.column("type", width=90, anchor="center")
        self.tree.column("size", width=120, anchor="e")
        self.tree.column("modify", width=160)

        vsb = ttk.Scrollbar(center, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.on_double_click)

        # =========================
        # Bottom: Log (하단 고정)
        # =========================
        log_frame = ttk.Frame(self)
        log_frame.pack(fill="x", expand=False, pady=(8, 0))

        log_header = ttk.Frame(log_frame)
        log_header.pack(fill="x")

        ttk.Label(log_header, text="로그").pack(side="left")
        ttk.Button(log_header, text="로그 지우기", command=self.clear_log).pack(side="right")

        self.txt_log = tk.Text(log_frame, height=9, wrap="word")
        self.txt_log.pack(fill="x", expand=False)

        self.refresh()

    def log(self, msg: str):
        self.log_q.put(msg)

    def append_log(self, msg: str):
        self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")

    def clear_log(self):
        self.txt_log.delete("1.0", "end")

    def change_local(self):
        d = filedialog.askdirectory(initialdir=self.cfg["local_dir"] or os.getcwd())
        if d:
            self.cfg["local_dir"] = d
            self.lbl_local.config(text=d)

    def clear_selection(self):
        self.tree.selection_remove(self.tree.selection())

    def select_all(self):
        items = self.tree.get_children()
        if items:
            self.tree.selection_set(items)

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        self.lbl_path.config(text=f"원격 경로: {self.current_dir}")

        try:
            items = self.client.list_dir(self.current_dir)
        except Exception as e:
            messagebox.showerror("조회 실패", f"{e}")
            return

        for it in items:
            t = "DIR" if it.is_dir else "FILE"
            size = "" if it.is_dir else (str(it.size) if it.size is not None else "")
            modify = it.modify or ""
            # iid를 name으로 사용(같은 폴더 내 중복 이름은 없음)
            self.tree.insert("", "end", iid=it.name, values=(it.name, t, size, modify))

    def on_double_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        name = row_id
        remote_path = self.current_dir.rstrip("/") + "/" + name
        try:
            if self.client.is_dir(remote_path):
                self.current_dir = remote_path
                self.refresh()
        except Exception:
            pass

    def go_up(self):
        if self.current_dir.rstrip("/") == self.cfg["remote_base"].rstrip("/"):
            return
        parent = posixpath.dirname(self.current_dir.rstrip("/"))
        if not parent:
            parent = "/"
        self.current_dir = parent
        self.refresh()

    def download_selected(self):
        selected = list(self.tree.selection())
        if not selected:
            messagebox.showinfo("안내", "선택된 항목이 없습니다.\n(Shift/Ctrl로 여러 개 선택 가능)")
            return

        local_base = self.cfg["local_dir"]
        if not local_base:
            messagebox.showerror("오류", "로컬 저장 폴더가 비어있습니다.")
            return

        targets = selected[:]

        def worker():
            self.log(f"=== 다운로드 시작: {self.current_dir} / {len(targets)}개 ===")
            for name in targets:
                remote_path = self.current_dir.rstrip("/") + "/" + name
                local_path = os.path.join(local_base, name)
                try:
                    if self.client.is_dir(remote_path):
                        self.log(f"[DIR] {remote_path}")
                        self.client.download_dir_recursive(remote_path, local_path, self.log)
                    else:
                        self.log(f"[GET] {remote_path}")
                        self.client.download_file(remote_path, local_path, self.log)
                except Exception as e:
                    self.log(f"[ERR] {remote_path}: {e}")
            self.log("=== 다운로드 완료 ===")

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = App()
    app.mainloop()
