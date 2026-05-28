"""Tkinter desktop client."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
from typing import Any

from secure_chat.client import ChatClient, ServerTrustError
from secure_chat.config import DEFAULT_FILE_RECEIVE_DIR, DEFAULT_RECEIVE_DIR
from secure_chat.file_transfer import (
    calculate_sha256,
    format_file_size,
    is_potentially_risky_file,
    verify_file_hash,
)
from secure_chat.packet_inspector import PacketInspectionEvent, format_packet_inspection_event
from secure_chat.utils import save_received_file


@dataclass(frozen=True)
class SecurityDashboardState:
    connection_state: str = "Disconnected"
    encryption_state: str = "Inactive"
    cipher: str = "PyNaCl Box"
    key_exchange: str = "PublicKey 기반"
    session_id: str = "-"
    local_fingerprint: str = "-"
    peer_fingerprint: str = "-"
    session_started_at: str = "-"
    sent_packet_count: int = 0
    received_packet_count: int = 0
    send_sequence: int = 0
    receive_sequence: int = 0
    last_replay_status: str = "Not checked"
    server_trust_status: str = "Unknown"
    tofu_verification: str = "Unknown"
    e2e_mode: str = "Unavailable"
    e2e_fingerprint: str = "-"
    selected_e2e_fingerprint: str = "-"
    last_e2e_decrypt_result: str = "Not checked"
    last_file_integrity: str = "N/A"
    last_received_message_type: str = "-"


def compact_fingerprint(fingerprint: str) -> str:
    if not fingerprint or fingerprint == "-":
        return "-"

    parts = fingerprint.split(":")
    if len(parts) <= 5:
        return fingerprint
    return f"{':'.join(parts[:3])}:...:{':'.join(parts[-2:])}"


def _format_datetime(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return "-"


def build_security_dashboard_state(
    client: Any | None,
    last_file_integrity: str = "N/A",
    selected_e2e_fingerprint: str = "-",
) -> SecurityDashboardState:
    metadata = getattr(client, "security_metadata", None) if client is not None else None
    connected = bool(client is not None and getattr(client, "connected", False))
    encryption_active = connected and metadata is not None

    if metadata is None:
        return SecurityDashboardState(
            selected_e2e_fingerprint=selected_e2e_fingerprint,
            last_file_integrity=last_file_integrity,
        )

    cipher = "PyNaCl Box" if "PyNaCl Box" in metadata.cipher else metadata.cipher
    return SecurityDashboardState(
        connection_state="Connected" if connected else "Disconnected",
        encryption_state="Active" if encryption_active else "Inactive",
        cipher=cipher,
        key_exchange="PublicKey 기반",
        session_id=metadata.session_id,
        local_fingerprint=compact_fingerprint(metadata.local_fingerprint),
        peer_fingerprint=compact_fingerprint(metadata.peer_fingerprint),
        session_started_at=_format_datetime(getattr(client, "connected_at", None)),
        sent_packet_count=int(getattr(client, "sent_packet_count", 0)),
        received_packet_count=int(getattr(client, "received_packet_count", 0)),
        send_sequence=int(getattr(client, "send_sequence", 0)),
        receive_sequence=int(getattr(client, "receive_sequence", 0)),
        last_replay_status=str(getattr(client, "last_replay_status", "Not checked") or "Not checked"),
        server_trust_status=str(getattr(client, "server_trust_status", "Unknown") or "Unknown"),
        tofu_verification=str(getattr(client, "tofu_verification", "Unknown") or "Unknown"),
        e2e_mode=str(getattr(client, "e2e_available", "Unavailable") or "Unavailable"),
        e2e_fingerprint=compact_fingerprint(str(getattr(client, "e2e_fingerprint", "-") or "-")),
        selected_e2e_fingerprint=compact_fingerprint(selected_e2e_fingerprint),
        last_e2e_decrypt_result=str(getattr(client, "last_e2e_decrypt_result", "Not checked") or "Not checked"),
        last_file_integrity=last_file_integrity,
        last_received_message_type=str(getattr(client, "last_received_message_type", "-") or "-"),
    )


class ChatApp:
    """Tkinter wrapper for the encrypted chat client."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str | None = None,
        receive_dir: str = DEFAULT_RECEIVE_DIR,
        file_receive_dir: str = DEFAULT_FILE_RECEIVE_DIR,
    ) -> None:
        self.host = host
        self.port = port
        self.username = (username or "").strip()
        self.receive_dir = Path(receive_dir)
        self.file_receive_dir = Path(file_receive_dir)
        self.client: ChatClient | None = None
        self.online_users: list[str] = []
        self.transcript_lines: list[str] = []
        self.packet_inspection_events: list[PacketInspectionEvent] = []
        self.last_file_integrity_result = "N/A"
        self.security_dashboard_state = SecurityDashboardState()

        self.win = tk.Tk()
        self.win.title("SecureSocketChat")
        self.win.geometry("1120x760")
        self.win.minsize(980, 680)

        self.security_vars: dict[str, tk.StringVar] = {}
        self.status_text = tk.StringVar(value="Ready")

        self._build_layout()
        self._refresh_security_panel()
        self.win.protocol("WM_DELETE_WINDOW", self.close)

    def run(self) -> None:
        if not self._start_client():
            return

        self._refresh_security_panel()
        self._add_chat_line("[보안] PyNaCl 공개키 교환 후 암호화 채널로 통신 중")
        self._add_chat_line("[보안] /security 명령어로 세션 fingerprint를 확인할 수 있습니다.")
        self._add_chat_line("[보안] /e2e 사용자명 메시지로 실험적 E2E whisper를 보낼 수 있습니다.")
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

        self.user_list = tk.Listbox(left_frame, width=31, height=9, exportselection=False)
        self.user_list.pack(fill=tk.X)
        self.user_list.insert(tk.END, "전체")
        self.user_list.selection_set(0)
        self.user_list.bind("<<ListboxSelect>>", self._on_user_selection_changed)

        hint_label = tk.Label(
            left_frame,
            text="대상 선택 후 전송하면\n1:1 귓속말로 전송됩니다.\n명령어: /w 이름 메시지",
            justify=tk.LEFT,
        )
        hint_label.pack(anchor="w", pady=(10, 0))

        security_frame = tk.LabelFrame(left_frame, text="Security Dashboard", padx=8, pady=8)
        security_frame.pack(fill=tk.X, pady=(12, 0))

        security_fields = [
            ("connection", "연결 상태"),
            ("encryption", "암호화 상태"),
            ("cipher", "암호화 방식"),
            ("key_exchange", "키 교환 방식"),
            ("session_id", "세션 ID"),
            ("local_fp", "내 공개키 FP"),
            ("peer_fp", "서버 공개키 FP"),
            ("started_at", "세션 시작"),
            ("sent_packets", "송신 패킷"),
            ("received_packets", "수신 패킷"),
            ("send_sequence", "송신 sequence"),
            ("receive_sequence", "수신 sequence"),
            ("replay_status", "Replay 검증"),
            ("server_trust", "서버 신뢰 상태"),
            ("tofu_result", "TOFU 검증"),
            ("e2e_mode", "E2E 모드"),
            ("e2e_fp", "내 E2E FP"),
            ("target_e2e_fp", "대상 E2E FP"),
            ("e2e_decrypt", "E2E 복호화"),
            ("file_integrity", "파일 무결성"),
            ("last_type", "마지막 수신 유형"),
        ]

        for row, (key, label_text) in enumerate(security_fields):
            self.security_vars[key] = tk.StringVar(value="-")
            tk.Label(security_frame, text=f"{label_text}:", anchor="w").grid(row=row, column=0, sticky="w")
            tk.Label(
                security_frame,
                textvariable=self.security_vars[key],
                anchor="w",
                justify=tk.LEFT,
                wraplength=135,
            ).grid(row=row, column=1, sticky="w", padx=(6, 0))

        security_frame.columnconfigure(1, weight=1)

        command_frame = tk.LabelFrame(left_frame, text="빠른 기능", padx=8, pady=8)
        command_frame.pack(fill=tk.X, pady=(12, 0))

        tk.Button(command_frame, text="보안정보", command=self._show_security_report).pack(fill=tk.X)
        tk.Button(command_frame, text="서버통계", command=self._request_stats).pack(fill=tk.X, pady=(5, 0))
        tk.Button(command_frame, text="대화저장", command=self._export_transcript).pack(fill=tk.X, pady=(5, 0))
        tk.Button(command_frame, text="화면지우기", command=self._clear_chat).pack(fill=tk.X, pady=(5, 0))

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        chat_frame = tk.Frame(right_frame)
        chat_frame.pack(fill=tk.BOTH, expand=True)

        self.chat_text = tk.Text(chat_frame, height=17, state=tk.DISABLED, wrap=tk.WORD)
        chat_scroll = tk.Scrollbar(chat_frame, command=self.chat_text.yview)
        self.chat_text.config(yscrollcommand=chat_scroll.set)
        chat_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inspector_frame = tk.LabelFrame(right_frame, text="Packet Inspector", padx=8, pady=8)
        inspector_frame.pack(fill=tk.X, pady=(10, 0))

        self.packet_inspector_text = tk.Text(
            inspector_frame,
            height=10,
            state=tk.DISABLED,
            wrap=tk.WORD,
            font=("Consolas", 9),
        )
        self.packet_inspector_text.pack(fill=tk.X)
        self._refresh_packet_inspector()

        bottom_frame = tk.Frame(self.win, padx=10, pady=10)
        bottom_frame.pack(fill=tk.X)

        self.input_box = tk.Entry(bottom_frame)
        self.input_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.input_box.bind("<Return>", self._send_message)

        send_button = tk.Button(bottom_frame, text="전송", width=10, command=self._send_message)
        send_button.pack(side=tk.LEFT, padx=(0, 6))

        e2e_button = tk.Button(bottom_frame, text="E2E 전송", width=10, command=self._send_e2e_message)
        e2e_button.pack(side=tk.LEFT, padx=(0, 6))

        image_button = tk.Button(bottom_frame, text="이미지", width=10, command=self._send_image)
        image_button.pack(side=tk.LEFT, padx=(0, 6))

        file_button = tk.Button(bottom_frame, text="파일", width=10, command=self._send_file)
        file_button.pack(side=tk.LEFT)

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
            self.client.connect(trust_decider=self._confirm_changed_server_fingerprint)
            self.status_text.set(f"Connected: {self.username} @ {self.host}:{self.port}")
            self._add_tofu_status_line()
            return True
        except OSError as exc:
            messagebox.showerror("접속 실패", f"서버에 접속할 수 없습니다.\n{exc}")
        except ServerTrustError as exc:
            messagebox.showwarning("서버 신뢰 검증 실패", str(exc))
        except Exception as exc:
            messagebox.showerror("접속 실패", f"암호화 연결을 만들 수 없습니다.\n{exc}")

        self.win.destroy()
        return False

    def _confirm_changed_server_fingerprint(self, result: Any) -> bool:
        message = (
            "이전에 저장된 서버 fingerprint와 현재 fingerprint가 다릅니다.\n\n"
            "서버가 변경되었거나 중간자 공격 가능성이 있습니다.\n\n"
            f"서버: {result.server_id}\n"
            f"저장된 fingerprint: {result.stored_fingerprint or '-'}\n"
            f"현재 fingerprint: {result.fingerprint}\n\n"
            "예를 선택하면 변경된 fingerprint를 신뢰하고 계속합니다.\n"
            "아니오를 선택하면 연결을 중단합니다."
        )
        return messagebox.askyesno("서버 fingerprint 변경 경고", message, parent=self.win)

    def _add_tofu_status_line(self) -> None:
        if self.client is None or self.client.trust_check_result is None:
            return

        result = self.client.trust_check_result
        if result.status == "New":
            self._add_chat_line("[보안] TOFU: 최초 접속 서버 fingerprint를 로컬 신뢰 저장소에 등록했습니다.")
        elif result.status == "Trusted":
            self._add_chat_line("[보안] TOFU: 저장된 서버 fingerprint와 일치합니다.")
        elif result.status == "Changed" and result.accepted:
            self._add_chat_line("[보안 경고] TOFU: 변경된 서버 fingerprint를 사용자가 신뢰하여 갱신했습니다.")
        elif result.status == "Changed":
            self._add_chat_line("[보안 경고] TOFU: 서버 fingerprint 변경이 감지되었습니다.")

    def _selected_target(self) -> str:
        selection = self.user_list.curselection()
        if not selection:
            return "전체"
        return self.user_list.get(selection[0])

    def _selected_target_e2e_fingerprint(self) -> str:
        if self.client is None:
            return "-"
        target = self._selected_target()
        metadata = self.client.get_e2e_metadata(target)
        if not metadata:
            return "-"
        return metadata.get("fingerprint", "-")

    def _on_user_selection_changed(self, _event: object | None = None) -> None:
        self._refresh_security_panel()

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
        self._refresh_security_panel()

    def _add_chat_line(self, text: str) -> None:
        self.transcript_lines.append(text)
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, text + "\n")
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def _process_messages(self) -> None:
        if self.client is None:
            return

        self._drain_packet_inspection_events()
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
            elif msg_type == "security_warning":
                self._add_chat_line(f"[보안 경고] {header.get('text', '')}")
            elif msg_type == "chat":
                self._add_chat_line(f"[전체] {header.get('from', '')}: {header.get('text', '')}")
            elif msg_type == "whisper":
                self._add_chat_line(f"[귓속말] {header.get('from', '')} -> {header.get('to', '')}: {header.get('text', '')}")
            elif msg_type == "e2e_whisper":
                self._add_chat_line(f"[E2E] {header.get('from', '')} -> {header.get('to', '')}: {header.get('text', '')}")
            elif msg_type == "image":
                self._handle_received_image(header, payload)
            elif msg_type == "file":
                self._handle_received_file(header, payload)
            elif msg_type == "stats":
                self._handle_stats(header)

        self._drain_packet_inspection_events()
        self._refresh_security_panel()
        self.win.after(100, self._process_messages)

    def _handle_received_image(self, header: dict, payload: bytes) -> None:
        sender = str(header.get("from", "unknown"))
        target = str(header.get("to", "전체"))
        filename = str(header.get("filename", "image.bin"))
        expected_hash = str(header.get("sha256", ""))
        actual_hash = calculate_sha256(payload)
        integrity = self._integrity_result(payload, expected_hash)
        self.last_file_integrity_result = integrity
        self._mark_latest_packet_integrity("image", integrity)

        size_text = format_file_size(len(payload))
        self._add_chat_line(f"[이미지] {sender} -> {target}: {filename} ({size_text}, SHA-256 {integrity})")
        if integrity == "FAIL":
            self._add_chat_line(f"        SHA-256 무결성 실패로 저장하지 않음 / {actual_hash[:16]}")
            return

        save_path = save_received_file(self.receive_dir, sender, filename, payload, fallback="image.bin")
        self._add_chat_line(f"        저장 위치: {save_path}")
        self._add_chat_line(f"        SHA-256 무결성: {integrity} / {actual_hash[:16]}")

    def _handle_received_file(self, header: dict, payload: bytes) -> None:
        sender = str(header.get("from", "unknown"))
        target = str(header.get("to", "전체"))
        filename = str(header.get("filename", "file.bin"))
        expected_hash = str(header.get("sha256", ""))
        actual_hash = calculate_sha256(payload)
        integrity = self._integrity_result(payload, expected_hash)
        self.last_file_integrity_result = integrity
        self._mark_latest_packet_integrity("file", integrity)

        size_text = format_file_size(len(payload))
        self._add_chat_line(f"[파일] {sender} -> {target}: {filename} ({size_text}, SHA-256 {integrity})")
        if integrity == "FAIL":
            self._add_chat_line(f"        SHA-256 무결성 실패로 저장하지 않음 / {actual_hash[:16]}")
            return

        save_path = save_received_file(self.file_receive_dir, sender, filename, payload, fallback="file.bin")
        self._add_chat_line(f"        저장 위치: {save_path}")
        self._add_chat_line(f"        SHA-256: {actual_hash[:16]}")

    def _integrity_result(self, payload: bytes, expected_hash: str) -> str:
        if not expected_hash:
            return "Unknown"
        return "OK" if verify_file_hash(payload, expected_hash) else "FAIL"

    def _handle_stats(self, header: dict) -> None:
        users = ", ".join(header.get("online_users", [])) or "없음"
        self._add_chat_line(
            "[서버통계] "
            f"uptime={header.get('uptime_seconds', 0)}s, "
            f"online={header.get('online_count', 0)}, "
            f"messages={header.get('total_messages', 0)}, "
            f"images={header.get('total_images', 0)}, "
            f"image_bytes={header.get('total_image_bytes', 0)}, "
            f"files={header.get('total_files', 0)}, "
            f"file_bytes={header.get('total_file_bytes', 0)}"
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
                self._drain_packet_inspection_events()
                self._refresh_security_panel()
                return

            if text.startswith("/e2e "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    self._add_chat_line("[사용법] /e2e 사용자명 메시지")
                    return
                target = parts[1].strip()
                message = parts[2].strip()
                self.client.send_e2e_whisper(target, message)
                self._add_chat_line(f"[E2E 전송] {self.username} -> {target}: {message}")
                self._drain_packet_inspection_events()
                self._refresh_security_panel()
                return

            target = self._selected_target()
            if target != "전체" and target != self.username:
                self.client.send_whisper(target, text)
            else:
                self.client.send_chat(text)
            self._drain_packet_inspection_events()
            self._refresh_security_panel()
        except OSError:
            self._drain_packet_inspection_events()
            self._add_chat_line("[오류] 메시지 전송 실패")
            self._refresh_security_panel()
        except ValueError as exc:
            self._drain_packet_inspection_events()
            self._add_chat_line(f"[오류] {exc}")
            self._refresh_security_panel()

    def _handle_local_command(self, text: str) -> bool:
        command = text.lower().strip()
        if command == "/help":
            self._add_chat_line("[명령어] /w 이름 메시지 | /e2e 이름 메시지 | /users | /security | /stats | /save | /clear | end")
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

    def _send_e2e_message(self) -> None:
        if self.client is None:
            return

        target = self._selected_target()
        text = self.input_box.get().strip()
        if not text:
            return

        try:
            self.client.send_e2e_whisper(target, text)
            self.input_box.delete(0, tk.END)
            self._add_chat_line(f"[E2E 전송] {self.username} -> {target}: {text}")
            self._drain_packet_inspection_events()
            self._refresh_security_panel()
        except ValueError as exc:
            self._add_chat_line(f"[오류] {exc}")
            self._refresh_security_panel()
        except OSError:
            self._drain_packet_inspection_events()
            self._add_chat_line("[오류] E2E 메시지 전송 실패")
            self._refresh_security_panel()

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
            self._drain_packet_inspection_events()
            self._refresh_security_panel()
        except ValueError as exc:
            messagebox.showerror("전송 실패", str(exc))
        except OSError:
            self._drain_packet_inspection_events()
            self._add_chat_line("[오류] 이미지 전송 실패")
            self._refresh_security_panel()

    def _send_file(self) -> None:
        if self.client is None:
            return

        file_path = filedialog.askopenfilename(
            title="전송할 파일 선택",
            filetypes=[("All files", "*.*")],
        )
        if not file_path:
            return

        filename = Path(file_path).name
        if is_potentially_risky_file(filename):
            should_continue = messagebox.askyesno(
                "위험 파일 경고",
                "실행 가능한 파일 또는 스크립트로 보이는 확장자입니다.\n"
                "수신자가 실행하면 보안 위험이 있을 수 있습니다.\n\n"
                "그래도 전송하시겠습니까?",
                parent=self.win,
            )
            if not should_continue:
                return

        target = self._selected_target()
        try:
            digest = self.client.send_file(target, file_path)
            size_text = format_file_size(Path(file_path).stat().st_size)
            self._add_chat_line(f"[전송] 파일 전송 요청: {filename} -> {target} ({size_text})")
            self._add_chat_line(f"        SHA-256: {digest[:16]}")
            self._drain_packet_inspection_events()
            self._refresh_security_panel()
        except ValueError as exc:
            messagebox.showerror("전송 실패", str(exc))
        except OSError:
            self._drain_packet_inspection_events()
            self._add_chat_line("[오류] 파일 전송 실패")
            self._refresh_security_panel()

    def _drain_packet_inspection_events(self) -> None:
        if self.client is None:
            self._refresh_packet_inspector()
            return

        changed = False
        while True:
            try:
                event = self.client.packet_events.get_nowait()
            except queue.Empty:
                break
            self.packet_inspection_events.append(event)
            self.packet_inspection_events = self.packet_inspection_events[-5:]
            changed = True

        if changed:
            self._refresh_packet_inspector()

    def _mark_latest_packet_integrity(self, logical_type: str, integrity_result: str) -> None:
        for index in range(len(self.packet_inspection_events) - 1, -1, -1):
            event = self.packet_inspection_events[index]
            if event.direction == "INBOUND" and event.logical_type == logical_type:
                self.packet_inspection_events[index] = replace(event, integrity_result=integrity_result)
                self._refresh_packet_inspector()
                return

    def _refresh_packet_inspector(self) -> None:
        if not hasattr(self, "packet_inspector_text"):
            return

        if self.packet_inspection_events:
            content = "\n\n".join(format_packet_inspection_event(event) for event in self.packet_inspection_events)
        else:
            content = "No packet captured yet."

        self.packet_inspector_text.config(state=tk.NORMAL)
        self.packet_inspector_text.delete("1.0", tk.END)
        self.packet_inspector_text.insert(tk.END, content)
        self.packet_inspector_text.config(state=tk.DISABLED)

    def _refresh_security_panel(self) -> None:
        state = build_security_dashboard_state(
            self.client,
            self.last_file_integrity_result,
            selected_e2e_fingerprint=self._selected_target_e2e_fingerprint(),
        )
        self.security_dashboard_state = state

        values = {
            "connection": state.connection_state,
            "encryption": state.encryption_state,
            "cipher": state.cipher,
            "key_exchange": state.key_exchange,
            "session_id": state.session_id,
            "local_fp": state.local_fingerprint,
            "peer_fp": state.peer_fingerprint,
            "started_at": state.session_started_at,
            "sent_packets": str(state.sent_packet_count),
            "received_packets": str(state.received_packet_count),
            "send_sequence": str(state.send_sequence),
            "receive_sequence": str(state.receive_sequence),
            "replay_status": state.last_replay_status,
            "server_trust": state.server_trust_status,
            "tofu_result": state.tofu_verification,
            "e2e_mode": state.e2e_mode,
            "e2e_fp": state.e2e_fingerprint,
            "target_e2e_fp": state.selected_e2e_fingerprint,
            "e2e_decrypt": state.last_e2e_decrypt_result,
            "file_integrity": state.last_file_integrity,
            "last_type": state.last_received_message_type,
        }
        for key, value in values.items():
            if key in self.security_vars:
                self.security_vars[key].set(value)

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
            self._drain_packet_inspection_events()
            self._refresh_security_panel()
        except OSError:
            self._drain_packet_inspection_events()
            self._add_chat_line("[오류] 서버 통계 요청 실패")
            self._refresh_security_panel()

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
