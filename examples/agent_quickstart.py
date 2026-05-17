"""
Minimum-viable swf-node integration for an agent.

Prereqs (in another shell):

    pipx install "git+https://github.com/dmarzzz/searxng-wth-frnds.git"
    swf-node &           # binds 127.0.0.1:7777

Then run this:

    python examples/agent_quickstart.py "your query here"

Hits POST /web_search and prints the top hits. Uses only the standard
library so you can drop it into any project without adding a dep.

The response shape (relevant fields):

    {
      "status": "ok" | "no_results" | "error",
      "delivery_path": "LOCAL_CACHE" | "LOCAL_INDREX" | "LAN_FRIEND_DIRECT" | "PUBLIC_FROM_SELF" | "NO_RESULT",
      "results": [
        {"title": "...", "canonical_url": "...", "snippet": "..."},
        ...
      ],
      ...
    }

The full envelope is documented in docs/HTTP_API.md.
"""

import json
import sys
import urllib.error
import urllib.request

NODE = "http://127.0.0.1:7777"


def web_search(query: str, top_k: int = 5, policy: str = "local_only") -> dict:
    """
    `policy` controls which delivery paths the router is allowed to use:
      - "local_only":  hits only the local indrex (no network)
      - "local_and_friends": local + LAN friends
      - "full":        local + friends + searxng fallback (may need
                       explicit confirmation for public egress; see
                       docs/SEARCH_POLICY_COOKBOOK.md)
    The quickstart defaults to "local_only" so a fresh install returns
    a clean response without prompting for egress consent. Bump to
    "full" once you've added friends or want public-web fallback.
    """
    body = json.dumps({"q": query, "top_k": top_k, "policy": policy}).encode()
    req = urllib.request.Request(
        f"{NODE}/web_search",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <query>", file=sys.stderr)
        return 1
    query = " ".join(sys.argv[1:])

    try:
        result = web_search(query)
    except urllib.error.URLError as exc:
        print(
            f"could not reach {NODE} ({exc.reason}). Is `swf-node` running?",
            file=sys.stderr,
        )
        return 2

    print(f"status:        {result.get('status')}")
    print(f"delivery_path: {result.get('delivery_path')}")
    hits = result.get("results", [])
    print(f"hits:          {len(hits)}\n")

    for i, hit in enumerate(hits, 1):
        print(f"{i}. {hit.get('title') or '(no title)'}")
        print(f"   {hit.get('canonical_url')}")
        snippet = (hit.get("snippet") or "").strip()
        if snippet:
            print(f"   {snippet[:160]}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
