"""
clean_server.py — Baseline "clean" MCP server.

This server is intentionally boring: a small set of file/notes utilities
with honest tool descriptions and no hidden behavior. It exists as the
negative control in the test bed — any scanner run against this server
should report zero (or near-zero) findings. If your detector flags things
here, that's a false-positive signal worth investigating.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-notes-server")

_NOTES: dict[str, str] = {}


@mcp.tool()
def save_note(title: str, content: str) -> str:
    """Save a note with the given title and content to the user's local
    notes store. Overwrites any existing note with the same title."""
    _NOTES[title] = content
    return f"Saved note '{title}' ({len(content)} chars)."


@mcp.tool()
def get_note(title: str) -> str:
    """Retrieve the content of a previously saved note by its title.
    Returns an error message if no note with that title exists."""
    return _NOTES.get(title, f"No note found with title '{title}'.")


@mcp.tool()
def list_notes() -> list[str]:
    """List the titles of all notes currently saved in the notes store."""
    return list(_NOTES.keys())


@mcp.tool()
def delete_note(title: str) -> str:
    """Delete the note with the given title. Returns a confirmation
    message whether or not the note existed."""
    existed = _NOTES.pop(title, None) is not None
    return f"Deleted note '{title}'." if existed else f"No note '{title}' to delete."


@mcp.tool()
def word_count(text: str) -> int:
    """Count the number of whitespace-separated words in the given text."""
    return len(text.split())


if __name__ == "__main__":
    mcp.run(transport="stdio")
