"""Self-sovereign web search, fetch, and indexing.

See `../../../DESIGN.md` for the full rationale. Short version: no API
keys by default, open-source infrastructure preferred (SearXNG, Nitter,
trafilatura), every crawl writes through to `world_knowledge/` so the
local knowledge base grows over time.

Public surface:

    from swf.web.providers import web_search, nitter_search
    from swf.web.fetch import fetch_url, fetch_urls_parallel
    from swf.web.crawl import extract_links
    from swf.web.knowledge import knowledge_root, world_write
    from swf.web.index import local_search, reindex_knowledge
"""
