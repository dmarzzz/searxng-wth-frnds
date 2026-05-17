"""`python -m swf` entry — equivalent to `swf-node`. Used by the
container ENTRYPOINT and by anyone running this from a clone without
the console script on PATH."""

from swf.peer_server import main

raise SystemExit(main())
