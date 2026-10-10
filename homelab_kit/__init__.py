"""Private documentation, with no background processes."""
import sys

if sys.version_info < (3, 11):  # noqa: UP036 - guard direct use on stock macOS
    raise SystemExit(
        "homelab-kit needs Python 3.11 or newer; you have "
        + ".".join(str(part) for part in sys.version_info[:3])
        + ". Install uv using the README Quickstart UV_INSTALL_DIR option for a separate tools directory.\n"
        "Then run: uv run --no-project --python 3.12 -- python -m homelab_kit init ../my-lab"
    )

__version__ = "0.2.0"
