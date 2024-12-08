import argparse


def serve_cmd(host, port):
    print(f"Serving on {host}:{port}")
    from sub_customizer.api.app import serve

    serve(host, port)


def main():
    parser = argparse.ArgumentParser(
        prog="sub-customizer", description="Clash subscription customizer."
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Sub-command help"
    )

    # Define the 'serve' command
    serve_parser = subparsers.add_parser(
        "serve", help="Serve customizer as http server."
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the server to (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=57890,
        help="Port to bind the server to (default: 57890)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        serve_cmd(args.host, args.port)


if __name__ == "__main__":
    main()
