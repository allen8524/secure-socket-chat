"""Tkinter desktop client."""

from __future__ import annotations

import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

from secure_chat.client import ChatClient
from secure_chat.config import DEFAULT_RECEIVE_DIR
from secure_chat.security import sha256_hex
from secure_chat.utils import save_received_file


class ChatApp:
    """Tkinter wrapper for the encrypted chat client."""

    def __init__(self, host: str, port: int, username: str | None = None, receive_dir: str = DEFAULT_RECEIVE_DIR) -> None:
        self.host = host
        self.port = port
        self.username = (username or "").strip()
        self.receive_dir = Path(receive_dir)
        self.client: ChatClient | None = None
        self.online_users: list[str] = []
        self.transcript_lines: list[str] = []

        self.win = tk.Tk()
        self.win.title("SecureSocketChat")
        self.win.geometry("860x600")
        self.win.minsize(780, 520)

        self.security_text = tk.StringVar(value="보안 세션: 연결 전")
        self.status_text = tk.StringVar(value="Ready")

        self._build_layout()
        self.win.protocol("WM_DELETE_WINDOW", self.close)

    def run(self) -> None:
        if not self._start_client():
            return

        self._refresh_security_panel()
        self._add_chat_line("[보안] PyNaCl 공개키 교환 후 암호화 채널로 통신 중")
        self._add_chat_line("[보안] /security 명령어로 세션 fingerprint를 확인할 수 있습니다.")
        self._add_chat_line("[사용법] /help 명령어로 사용 가능한 기능을 확인하세요.")
        self._process_messages()
        self.input_box.focus()
        self.win.mainloop()

    def _build_layout(self) -> None:
        main_frame = tk.Frame(self.win, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        user_label = tk.Label(left_frame, text="접속자 / 귓속말 대상")
        user_label.pack(anchor="w")

        self.user_list = tk.Listbox(left_frame, width=24, height=18, exportselection=False)
        self.user_list.pack(fill=tk.Y, expand=True)
        self.user_list.insert(tk.END, "전체")
        self.user_list.selection_set(0)

        hint_label = tk.Label(
            left_frame,
            text="대상 선택 후 전송하면\n1:1 귓속말로 전송됩니다.\n명령어: /w 이름 메시지",
            justify=tk.LEFT,
        )
        hint_label.pack(anchor="w", pady=(10, 0))

        security_frame = tk.LabelFrame(left_frame, text="보안 세션", padx=8, pady=8)
        security_frame.pack(fill=tk.X, pady=(12, 0))

        security_label = tk.Label(security_frame, textvariable=self.security_text, justify=tk.LEFT, wraplength=170)
        security_label.pack(anchor="w")

        command_frame = tk.LabelFrame(left_frame, text="빠른 기능", padx=8, pady=8)
        command_frame.pack(fill=tk.X, pady=(12, 0))

        tk.Button(command_frame, text="보안정보", command=self._show_security_report).pack(fill=tk.X)
        tk.Button(command_frame, text="서버통계", command=self._request_stats).pack(fill=tk.X, pady=(5, 0))
        tk.Button(command_frame, text="대화저장", command=self._export_transcript).pack(fill=tk.X, pady=(5, 0))
        tk.Button(command_frame, text="화면지우기", command=self._clear_chat).pack(fill=tk.X, pady=(5, 0))

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.chat_text = tk.Text(right_frame, height=20, state=tk.DISABLED, wrap=tk.WORD)
        chat_scroll = tk.Scrollbar(right_frame, command=self.chat_text.yview)
        self.chat_text.config(yscrollcommand=chat_scroll.set)
        chat_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        bottom_frame = tk.Frame(self.win, padx=10, pady=10)
        bottom_frame.pack(fill=tk.X)

        self.input_box = tk.Entry(bottom_frame)
        self.input_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.input_box.bind("<Return>", self._send_message)

        send_button = tk.Button(bottom_frame, text="전송", width=10, command=self._send_message)
        send_button.pack(side=tk.LEFT, padx=(0, 6))

        image_button = tk.Button(bottom_frame, text="이미지", width=10, command=self._send_image)
        image_button.pack(side=tk.LEFT)

        status_bar = tk.Label(self.win, textvariable=self.status_text, anchor="w", relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _start_client(self) -> bool:
        if not self.username:
            entered_name = simpledialog.askstring("이름 입력", "채팅에서 사용할 이름을 입력하세요.", parent=self.win)
            self.username = (entered_name or "").strip()

        if not self.username:
            messagebox.showerror("실행 실패", "이름을 입력해야 합니다.")
            self.win.destroy()
            return False

        self.client = ChatClient(self.host, self.port, self.username)
        try:
            self.client.connect()
            self.status_text.set(f"Connected: {self.username} @ {self.host}:{self.port}")
            return True
        except OSError as exc:
            messagebox.showerror("접속 실패", f"서버에 접속할 수 없습니다.\n{exc}")
        except Exception as exc:
            messagebox.showerror("접속 실패", f"암호화 연결을 만들 수 없습니다.\n{exc}")

        self.win.destroy()
        return False

    def _selected_target(self) -> str:
        selection = self.user_list.curselection()
        if not selection:
            return "전체"
        return self.user_list.get(selection[0])

    def _update_user_list(self, users: list[str]) -> None:
        self.online_users = users
        current_target = self._selected_target()
        self.user_list.delete(0, tk.END)
        self.user_list.insert(tk.END, "전체")

        for user in users:
            self.user_list.insert(tk.END, user)

        available_targets = {self.user_list.get(i) for i in range(self.user_list.size())}
        target_to_select = current_target if current_target in available_targets else "전체"
        for index in range(self.user_list.size()):
            if self.user_list.get(index) == target_to_select:
                self.user_list.selection_set(index)
                break

        self.status_text.set(f"Online: {len(users)}명 | Target: {target_to_select}")

    def _add_chat_line(self, text: str) -> None:
        self.transcript_lines.append(text)
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, text + "\n")
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def _process_messages(self) -> None:
        if self.client is None:
            return

        while True:
            try:
                header, payload = self.client.inbox.get_nowait()
            except queue.Empty:
                break

            msg_type = header.get("type")
            if msg_type == "users":
                self._update_user_list(list(header.get("users", [])))
            elif msg_type == "system":
                self._add_chat_line(f"[알림] {header.get('text', '')}")
            elif msg_type == "error":
                self._add_chat_line(f"[오류] {header.get('text', '')}")
            elif msg_type == "chat":
                self._add_chat_line(f"[전체] {header.get('from', '')}: {header.get('text', '')}")
            elif msg_type == "whisper":
                self._add_chat_line(f"[귓속말] {header.get('from', '')} -> {header.get('to', '')}: {header.get('text', '')}")
            elif msg_type == "image":
                self._handle_received_image(header, payload)
            elif msg_type == "stats":
                self._handle_stats(header)

        self.win.after(100, self._process_messages)

    def _handle_received_image(self, header: dict, payload: bytes) -> None:
        sender = str(header.get("from", "unknown"))
        target = str(header.get("to", "전체"))
        filename = str(header.get("filename", "image.bin"))
        expected_hash = str(header.get("sha256", ""))
        actual_hash = sha256_hex(payload)
        integrity = "OK" if expected_hash and expected_hash == actual_hash else "확인불가"
        if expected_hash and expected_hash != actual_hash:
            integrity = "FAIL"

        save_path = save_received_file(self.receive_dir, sender, filename, payload)
        self._add_chat_line(f"[이미지] {sender} -> {target}: {filename} ({len(payload)} bytes)")
        self._add_chat_line(f"        저장 위치: {save_path}")
        self._add_chat_line(f"        SHA-256 무결성: {integrity} / {actual_hash[:16]}")

    def _handle_stats(self, header: dict) -> None:
        users = ", ".join(header.get("online_users", [])) or "없음"
        self._add_chat_line(
            "[서버통계] "
            f"uptime={header.get('uptime_seconds', 0)}s, "
            f"online={header.get('online_count', 0)}, "
            f"messages={header.get('total_messages', 0)}, "
            f"images={header.get('total_images', 0)}, "
            f"image_bytes={header.get('total_image_bytes', 0)}"
        )
        self._add_chat_line(f"[서버통계] users={users}")

    def _send_message(self, event: object | None = None) -> None:
        if self.client is None:
            return

        text = self.input_box.get().strip()
        if not text:
            return

        self.input_box.delete(0, tk.END)

        try:
            if self._handle_local_command(text):
                return

            if text == "end":
                self.close()
                return

            if text.startswith("/w "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    self._add_chat_line("[사용법] /w 사용자명 메시지")
                    return
                self.client.send_whisper(parts[1].strip(), parts[2].strip())
                return

            target = self._selected_target()
            if target != "전체" and target != self.username:
                self.client.send_whisper(target, text)
            else:
                self.client.send_chat(text)
        except OSError:
            self._add_chat_line("[오류] 메시지 전송 실패")

    def _handle_local_command(self, text: str) -> bool:
        command = text.lower().strip()
        if command == "/help":
            self._add_chat_line("[명령어] /w 이름 메시지 | /users | /security | /stats | /save | /clear | end")
            return True
        if command == "/users":
            users = ", ".join(self.online_users) or "없음"
            self._add_chat_line(f"[접속자] {users}")
            return True
        if command == "/security":
            self._show_security_report()
            return True
        if command == "/stats":
            self._request_stats()
            return True
        if command == "/save":
            self._export_transcript()
            return True
        if command == "/clear":
            self._clear_chat()
            return True
        return False

    def _send_image(self) -> None:
        if self.client is None:
            return

        file_path = filedialog.askopenfilename(
            title="전송할 이미지 선택",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"), ("All files", "*.*")],
        )
        if not file_path:
            return

        target = self._selected_target()
        try:
            digest = self.client.send_image(target, file_path)
            self._add_chat_line(f"[전송] 이미지 전송 요청: {Path(file_path).name} -> {target}")
            self._add_chat_line(f"        SHA-256: {digest[:16]}")
        except ValueError as exc:
            messagebox.showerror("전송 실패", str(exc))
        except OSError:
            self._add_chat_line("[오류] 이미지 전송 실패")

    def _refresh_security_panel(self) -> None:
        if self.client is None or self.client.security_metadata is None:
            self.security_text.set("보안 세션: 연결 전")
            return

        metadata = self.client.security_metadata
        self.security_text.set(
            f"Cipher: {metadata.cipher}\n"
            f"Session: {metadata.session_id}\n"
            f"Client FP: {metadata.local_fingerprint}\n"
            f"Server FP: {metadata.peer_fingerprint}"
        )

    def _show_security_report(self) -> None:
        if self.client is None:
            self._add_chat_line("[보안] 연결된 클라이언트가 없습니다.")
            return
        self._refresh_security_panel()
        self._add_chat_line(f"[보안] {self.client.security_report()}")

    def _request_stats(self) -> None:
        if self.client is None:
            return
        try:
            self.client.request_stats()
        except OSError:
            self._add_chat_line("[오류] 서버 통계 요청 실패")

    def _export_transcript(self) -> None:
        default_name = f"secure_chat_transcript_{self.username or 'user'}.txt"
        path = filedialog.asksaveasfilename(
            title="대화 로그 저장",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        security_report = self.client.security_report() if self.client is not None else "보안 세션 정보 없음"
        content = ["SecureSocketChat Transcript", "", f"Security: {security_report}", ""]
        content.extend(self.transcript_lines)
        Path(path).write_text("\n".join(content), encoding="utf-8")
        self._add_chat_line(f"[저장] 대화 로그 저장 완료: {path}")

    def _clear_chat(self) -> None:
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)
        self.chat_text.config(state=tk.DISABLED)
        self.status_text.set("Chat view cleared")

    def close(self) -> None:
        if self.client is not None:
            self.client.leave()
            self.client = None
        self.win.destroy()
