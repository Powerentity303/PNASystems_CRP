"""Background entry: reloads vault password from env, runs the listener."""
import getpass
import os

from pnasyscnct.pi_daemon import run_forever


def main() -> None:
    if "PNASYS_PW" not in os.environ:
        if os.isatty(0):
            os.environ["PNASYS_PW"] = getpass.getpass("Local encryption password: ")
        else:
            raise SystemExit("PNASYS_PW not set for background service")
    run_forever()


if __name__ == "__main__":
    main()
