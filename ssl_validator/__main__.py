"""`python -m ssl_validator` starts the GUI; `python -m ssl_validator validate|compare ...` uses the CLI."""
import sys

if len(sys.argv) > 1:
    from .cli import main
else:
    from .gui import main

sys.exit(main())
