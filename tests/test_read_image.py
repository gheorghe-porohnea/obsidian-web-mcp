"""Tests for vault_read_image."""

import json

from mcp.server.fastmcp import Image

from obsidian_vault_mcp.tools.read import vault_read_image

# A few bytes that need not be a real PNG -- only the extension is checked.
_PNG_BYTES = b"\x89PNG\r\n\x1a\n fake-image-bytes"


def test_reads_png_as_image_content(vault_dir):
    (vault_dir / "pic.png").write_bytes(_PNG_BYTES)
    result = vault_read_image("pic.png")
    assert isinstance(result, Image)
    assert result.data == _PNG_BYTES


def test_rejects_unsupported_extension(vault_dir):
    (vault_dir / "doc.pdf").write_bytes(b"%PDF-1.4 fake")
    result = json.loads(vault_read_image("doc.pdf"))
    assert "error" in result
    assert result["path"] == "doc.pdf"


def test_missing_file_returns_error(vault_dir):
    result = json.loads(vault_read_image("nope.png"))
    assert "not found" in result["error"].lower()


# --- boundaries shared with the other read tools ------------------------------------------

import asyncio
import os

import pytest

from obsidian_vault_mcp import config, server


def call_tool(name: str, arguments: dict):
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    return result[0] if isinstance(result, tuple) else result


def test_registered_tool_returns_image_content(vault_dir):
    (vault_dir / "pic.png").write_bytes(_PNG_BYTES)
    blocks = call_tool("vault_read_image", {"path": "pic.png"})
    assert [b.type for b in blocks] == ["image"]
    assert blocks[0].mimeType == "image/png"


def test_extension_check_is_case_insensitive(vault_dir):
    (vault_dir / "PIC.JPG").write_bytes(_PNG_BYTES)
    assert isinstance(vault_read_image("PIC.JPG"), Image)


@pytest.mark.parametrize("path", ["../escape.png", ".hidden/pic.png", ".secret.png"])
def test_refuses_paths_outside_the_readable_vault(vault_dir, path):
    result = json.loads(vault_read_image(path))
    assert "error" in result


def test_refuses_a_hardlinked_image(vault_dir, tmp_path):
    source = tmp_path / "outside.png"
    source.write_bytes(_PNG_BYTES)
    os.link(source, vault_dir / "linked.png")
    result = json.loads(vault_read_image("linked.png"))
    assert "hardlink" in result["error"].lower()


def test_refuses_a_symlink_that_leaves_the_vault(vault_dir, tmp_path):
    source = tmp_path / "outside.png"
    source.write_bytes(_PNG_BYTES)
    (vault_dir / "sym.png").symlink_to(source)
    assert "error" in json.loads(vault_read_image("sym.png"))


def test_refuses_an_oversized_image_without_reading_it(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "MAX_BINARY_SIZE", 16)
    (vault_dir / "big.png").write_bytes(b"x" * 17)
    assert "exceeds limit" in json.loads(vault_read_image("big.png"))["error"]
    (vault_dir / "ok.png").write_bytes(b"x" * 16)
    assert isinstance(vault_read_image("ok.png"), Image)


def test_a_directory_named_like_an_image_is_not_a_file(vault_dir):
    (vault_dir / "dir.png").mkdir()
    assert "not found" in json.loads(vault_read_image("dir.png"))["error"].lower()
