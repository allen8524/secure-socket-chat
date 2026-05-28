from __future__ import annotations

import argparse

from secure_chat.config import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_RECEIVE_DIR
from secure_chat.gui import ChatApp
from secure_chat.logging_config import configure_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SecureSocketChat GUI client.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="server port")
    parser.add_argument("--name", default="", help="chat username")
    parser.add_argument("--receive-dir", default=DEFAULT_RECEIVE_DIR, help="directory for received images")
    parser.add_argument("--verbose", action="store_true", help="enable debug logs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(verbose=args.verbose)
    app = ChatApp(args.host, args.port, args.name, args.receive_dir)
    app.run()


if __name__ == "__main__":
    main()
