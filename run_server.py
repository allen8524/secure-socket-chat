from __future__ import annotations

import argparse

from secure_chat.config import DEFAULT_HOST, DEFAULT_PORT
from secure_chat.logging_config import configure_logging
from secure_chat.server import ChatServer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SecureSocketChat server.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="server bind host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="server bind port")
    parser.add_argument(
        "--server-key-file",
        default=None,
        help="optional path for a persistent server transport private key",
    )
    parser.add_argument("--verbose", action="store_true", help="enable debug logs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(verbose=args.verbose)
    server = ChatServer(args.host, args.port, server_key_file=args.server_key_file)

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
