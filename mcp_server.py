# mcp_server.py — adaptateur MCP autour du moteur stdlib-only
# Le cœur (skill_to_humans.py) n'est PAS modifié.
# Dépendance : pip install "mcp<2" (v1.x — l'API 2.x a renommé FastMCP en MCPServer)
from mcp.server.fastmcp import FastMCP
import skill_to_humans as m

mcp = FastMCP("skill-to-humans", host="127.0.0.1", port=8000)


@mcp.tool()
def reveal(content: str, filename: str = "input.txt") -> str:
    """Reveal hidden content (zero-width characters, Unicode tags, nested
    base64, bidi overrides, homoglyphs) the way an LLM agent would read it.
    Verdict-free: shows facts, never says safe or malicious. Judgment stays
    with the reader."""
    rendered, ctx = m.render_text(content)
    return m.full_output(filename, rendered, ctx, [])


if __name__ == "__main__":
    mcp.run(transport="streamable-http")