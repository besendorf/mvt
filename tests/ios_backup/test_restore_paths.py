# Mobile Verification Toolkit (MVT)
# Copyright (c) 2026 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import hashlib
import json
import os
import plistlib
import sqlite3
import struct

import pytest
from click.testing import CliRunner
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from mvt.ios.cli import decrypt_backup, extract_key


def _encrypted_backup(tmp_path, entries):
    """Build a small encrypted backup, including its keybag and manifest."""
    backup = tmp_path / "backup"
    backup.mkdir()
    password = "test-password"
    salt, dpsl = b"s" * 20, b"d" * 20
    password_key = hashlib.pbkdf2_hmac(
        "sha1",
        hashlib.pbkdf2_hmac("sha256", password.encode(), dpsl, 1, 32),
        salt,
        1,
        32,
    )
    class_key, manifest_key, file_key = b"c" * 32, b"m" * 32, b"f" * 32

    def wrap(key, value):
        return AES.new(key, AES.MODE_KW).seal(value)

    def encrypt(data, key):
        return AES.new(key, AES.MODE_CBC, iv=b"\0" * 16).encrypt(pad(data, 16))

    keybag = b""
    for tag, value in [
        (b"VERS", 3),
        (b"TYPE", 1),
        (b"UUID", b"u" * 16),
        (b"WRAP", 2),
        (b"SALT", salt),
        (b"ITER", 1),
        (b"DPSL", dpsl),
        (b"DPIC", 1),
        (b"UUID", b"v" * 16),
        (b"CLAS", 1),
        (b"WRAP", 2),
        (b"WPKY", wrap(password_key, class_key)),
    ]:
        if isinstance(value, int):
            value = struct.pack(">I", value)
        keybag += tag + struct.pack(">I", len(value)) + value

    manifest = tmp_path / "manifest.sqlite"
    file_ids = []
    with sqlite3.connect(manifest) as conn:
        conn.execute(
            "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, "
            "flags INTEGER, file BLOB)"
        )
        for index, (domain, relative_path, content) in enumerate(entries):
            file_id = hashlib.sha1(str(index).encode()).hexdigest()
            file_ids.append(file_id)
            metadata = plistlib.dumps(
                {
                    "$objects": [
                        "$null",
                        {
                            "Size": len(content),
                            "ProtectionClass": 1,
                            "EncryptionKey": plistlib.UID(2),
                        },
                        {"NS.data": struct.pack("<I", 1) + wrap(class_key, file_key)},
                    ],
                    "$top": {"root": plistlib.UID(1)},
                },
                fmt=plistlib.FMT_BINARY,
            )
            conn.execute(
                "INSERT INTO Files VALUES (?, ?, ?, 1, ?)",
                (file_id, domain, relative_path, metadata),
            )
            source = backup / file_id[:2] / file_id
            source.parent.mkdir(exist_ok=True)
            source.write_bytes(encrypt(content, file_key))
    conn.close()
    (backup / "Manifest.db").write_bytes(encrypt(manifest.read_bytes(), manifest_key))
    (backup / "Manifest.plist").write_bytes(
        plistlib.dumps(
            {
                "IsEncrypted": True,
                "BackupKeyBag": keybag,
                "ManifestKey": struct.pack("<I", 1) + wrap(class_key, manifest_key),
            }
        )
    )
    return backup, password, file_ids


@pytest.mark.parametrize("jobs", [1, 2])
@pytest.mark.parametrize("restore_paths", [False, True])
@pytest.mark.parametrize("hashes", [False, True])
def test_decrypt_backup_restores_paths_without_changing_backup_layout(
    tmp_path, jobs, restore_paths, hashes
):
    entries = [
        ("HomeDomain", "Library/Notes/notes with spaces.txt", b"home notes\x00\xff"),
        (
            "AppDomain-org.example.notes",
            "Library/Notes/notes with spaces.txt",
            b"app notes",
        ),
        ("HomeDomain", "Library/Notes/café.txt", b"unicode filename"),
    ]
    backup, password, file_ids = _encrypted_backup(tmp_path, entries)
    encrypted_manifest = (backup / "Manifest.db").read_bytes()
    destination = tmp_path / "destination"
    args = ["-d", str(destination), "-p", password, "--jobs", str(jobs), str(backup)]
    if restore_paths:
        args.insert(0, "--restore-paths")
    if hashes:
        args.insert(0, "--hashes")

    result = CliRunner().invoke(decrypt_backup, args)

    assert result.exit_code == 0, result.output
    for file_id, (domain, relative_path, content) in zip(file_ids, entries):
        assert (destination / file_id[:2] / file_id).read_bytes() == content
        if restore_paths:
            assert (
                destination / "restored" / domain / relative_path
            ).read_bytes() == content
    assert (backup / "Manifest.db").read_bytes() == encrypted_manifest
    assert (destination / "restored").exists() == restore_paths
    with sqlite3.connect(destination / "Manifest.db") as conn:
        assert conn.execute("SELECT count(*) FROM Files").fetchone()[0] == len(entries)
    assert (destination / "Manifest.plist").is_file()
    if hashes:
        info = json.loads((destination / "info.json").read_text())
        digests = {entry["file_path"]: entry["sha256"] for entry in info["decrypted"]}
        for file_id, (domain, relative_path, content) in zip(file_ids, entries):
            digest = hashlib.sha256(content).hexdigest()
            assert digests[str(destination / file_id[:2] / file_id)] == digest
            if restore_paths:
                assert (
                    digests[str(destination / "restored" / domain / relative_path)]
                    == digest
                )


@pytest.mark.parametrize(
    "domain,relative_path",
    [
        ("../outside", "file"),
        ("/absolute", "file"),
        ("HomeDomain/other", "file"),
        ("HomeDomain\\other", "file"),
        ("C:relative", "file"),
        ("", "file"),
        (None, "file"),
        ("HomeDomain", "../../outside"),
        ("HomeDomain", "/absolute"),
        ("HomeDomain", "C:/absolute"),
        ("HomeDomain", "..\\outside"),
        ("HomeDomain", "Library/../outside"),
        ("HomeDomain", "Library//file"),
        ("HomeDomain", "Library/./file"),
        ("HomeDomain", "file\0name"),
        ("HomeDomain", ""),
        ("HomeDomain", None),
        *[
            pytest.param(
                "HomeDomain",
                path,
                marks=pytest.mark.skipif(
                    os.name != "nt", reason="Windows filename restrictions"
                ),
            )
            for path in ["file:stream", "NUL.txt", "file.", "file ", "a?b", "a\x01b"]
        ],
    ],
)
def test_unsafe_restored_paths_keep_the_standard_backup(
    tmp_path, caplog, domain, relative_path
):
    backup, password, file_ids = _encrypted_backup(
        tmp_path, [(domain, relative_path, b"content")]
    )
    destination = tmp_path / "destination"

    result = CliRunner().invoke(
        decrypt_backup,
        ["--restore-paths", "-d", str(destination), "-p", password, str(backup)],
    )

    assert result.exit_code == 0, result.output
    assert (destination / file_ids[0][:2] / file_ids[0]).read_bytes() == b"content"
    assert "Could not restore file" in caplog.text
    assert not (tmp_path / "outside").exists()
    assert not (destination / "restored").exists()


@pytest.mark.parametrize("jobs", [1, 2])
@pytest.mark.parametrize(
    "second_path",
    [
        "Library/file.txt",
        pytest.param(
            "library/FILE.txt",
            marks=pytest.mark.skipif(os.name != "nt", reason="Windows case folding"),
        ),
    ],
)
def test_restoring_duplicate_paths_does_not_overwrite_files(
    tmp_path, caplog, jobs, second_path
):
    entries = [
        ("HomeDomain", "Library/file.txt", b"first"),
        ("HomeDomain", second_path, b"second"),
    ]
    backup, password, file_ids = _encrypted_backup(tmp_path, entries)
    destination = tmp_path / "destination"

    result = CliRunner().invoke(
        decrypt_backup,
        [
            "--restore-paths",
            "-d",
            str(destination),
            "-p",
            password,
            "--jobs",
            str(jobs),
            str(backup),
        ],
    )

    assert result.exit_code == 0, result.output
    for file_id, (_, _, content) in zip(file_ids, entries):
        assert (destination / file_id[:2] / file_id).read_bytes() == content
    assert (destination / "restored/HomeDomain/Library/file.txt").read_bytes() in (
        b"first",
        b"second",
    )
    assert "Could not restore file" in caplog.text


@pytest.mark.parametrize("jobs", [1, 2])
def test_restoring_file_directory_collisions_preserves_both_backup_files(
    tmp_path, caplog, jobs
):
    entries = [
        ("HomeDomain", "Library/file", b"first"),
        ("HomeDomain", "Library/file/nested", b"second"),
    ]
    backup, password, file_ids = _encrypted_backup(tmp_path, entries)
    destination = tmp_path / "destination"

    result = CliRunner().invoke(
        decrypt_backup,
        [
            "--restore-paths",
            "-d",
            str(destination),
            "-p",
            password,
            "--jobs",
            str(jobs),
            str(backup),
        ],
    )

    assert result.exit_code == 0, result.output
    for file_id, (_, _, content) in zip(file_ids, entries):
        assert (destination / file_id[:2] / file_id).read_bytes() == content
    restored_root = destination / "restored"
    restored_files = {
        path.relative_to(restored_root).as_posix(): path.read_bytes()
        for path in restored_root.rglob("*")
        if path.is_file()
    }
    assert restored_files in [
        {"HomeDomain/Library/file": b"first"},
        {"HomeDomain/Library/file/nested": b"second"},
    ]
    assert "Could not restore file" in caplog.text


def test_restoring_paths_with_an_exported_decryption_key(tmp_path):
    backup, password, _ = _encrypted_backup(
        tmp_path, [("HomeDomain", "Library/file.txt", b"content")]
    )
    key_file = tmp_path / "backup.key"
    result = CliRunner().invoke(
        extract_key, ["-p", password, "-k", str(key_file), str(backup)]
    )
    assert result.exit_code == 0, result.output
    destination = tmp_path / "destination"

    result = CliRunner().invoke(
        decrypt_backup,
        ["--restore-paths", "-d", str(destination), "-k", str(key_file), str(backup)],
    )

    assert result.exit_code == 0, result.output
    assert (
        destination / "restored/HomeDomain/Library/file.txt"
    ).read_bytes() == b"content"


def test_restoring_paths_does_not_overwrite_existing_files(tmp_path, caplog):
    backup, password, _ = _encrypted_backup(
        tmp_path, [("HomeDomain", "Library/file.txt", b"new content")]
    )
    destination = tmp_path / "destination"
    existing = destination / "restored/HomeDomain/Library/file.txt"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"existing content")

    result = CliRunner().invoke(
        decrypt_backup,
        ["--restore-paths", "-d", str(destination), "-p", password, str(backup)],
    )

    assert result.exit_code == 0, result.output
    assert existing.read_bytes() == b"existing content"
    assert "Could not restore file" in caplog.text


@pytest.mark.parametrize("link_at", ["restored", "restored/HomeDomain/Library"])
def test_restoring_paths_does_not_follow_symlinks_outside_export(
    tmp_path, caplog, link_at
):
    backup, password, file_ids = _encrypted_backup(
        tmp_path, [("HomeDomain", "Library/file.txt", b"content")]
    )
    destination = tmp_path / "destination"
    outside = tmp_path / "outside"
    outside.mkdir()
    link = destination / link_at
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating symbolic links is not permitted on this system")

    result = CliRunner().invoke(
        decrypt_backup,
        ["--restore-paths", "-d", str(destination), "-p", password, str(backup)],
    )

    assert result.exit_code == 0, result.output
    assert (destination / file_ids[0][:2] / file_ids[0]).read_bytes() == b"content"
    assert list(outside.iterdir()) == []
    assert "Could not restore file" in caplog.text
