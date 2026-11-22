import hashlib
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock, Timeout
from platformdirs import user_data_path

from .model import Error, Target


class Store:
    def __init__(self):
        configured = Path(os.environ.get("HPT_SIEM_DATA_DIR") or user_data_path("HPT_SIEM_ELK_Skills"))
        configured.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = configured.resolve(strict=True)
        self.service = "HPT_SIEM_ELK_Skills/" + hashlib.sha256(
            os.fsencode(os.path.normcase(self.root))).hexdigest()
        with self.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY, binding TEXT UNIQUE NOT NULL, config TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0, encrypted BLOB
            )""")

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.root / "registry.sqlite3", timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def locked(self, key):
        try:
            with FileLock(str(self.root / (key + ".lock")), timeout=45):
                yield
        except Timeout:
            raise Error("session_busy", "The local session is busy. Retry the operation.") from None

    def register(self, target, use_existing_id=False):
        with self.locked("registry"), self.db() as db:
            row = db.execute("SELECT config FROM targets WHERE binding = ?", (target.lock_key,)).fetchone()
            if row:
                existing = Target(**json.loads(row[0]))
                if existing.id != target.id and not use_existing_id:
                    raise Error("target_conflict", "This deployment and auth context already have a SIEM ID.")
                if target.allow_http and not existing.allow_http:
                    existing = replace(existing, allow_http=True)
                    db.execute("UPDATE targets SET config = ? WHERE id = ?",
                               (json.dumps(existing.public()), existing.id))
                return existing
            try:
                db.execute("INSERT INTO targets (id, binding, config) VALUES (?, ?, ?)",
                           (target.id, target.lock_key, json.dumps(target.public())))
            except sqlite3.IntegrityError:
                raise Error("target_conflict", "This SIEM ID already belongs to another deployment or context.") from None
        return target

    def get(self, siem_id):
        with self.db() as db:
            row = db.execute("SELECT config FROM targets WHERE id = ?", (siem_id,)).fetchone()
        if not row:
            raise Error("unknown_siem", "Register a Kibana URL or select an existing SIEM ID.")
        return Target(**json.loads(row[0]))

    def list(self):
        with self.db() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT config FROM targets ORDER BY id")]

    def cipher(self, create=False):
        with self.locked("credential-key"):
            try:
                if sys.platform == "win32":
                    from keyring.backends.Windows import WinVaultKeyring
                    vault = WinVaultKeyring()
                    vault.persist = "local machine"
                elif sys.platform == "darwin":
                    from keyring.backends.macOS import Keyring
                    vault = Keyring()
                else:
                    from keyring.backends.SecretService import Keyring
                    vault = Keyring()
                key = vault.get_password(self.service, "encryption-key")
                if key is None and create:
                    with self.db() as db:
                        if db.execute("SELECT 1 FROM targets WHERE encrypted IS NOT NULL LIMIT 1").fetchone():
                            raise Error("credential_store_unavailable",
                                        "The vault key is missing for existing encrypted sessions.")
                    key = Fernet.generate_key().decode("ascii")
                    vault.set_password(self.service, "encryption-key", key)
                return Fernet(key.encode("ascii"))
            except Error:
                raise
            except Exception:
                raise Error("credential_store_unavailable",
                            "Unlock or configure your native OS credential store and retry.") from None

    def load(self, target):
        with self.db() as db:
            generation, encrypted = db.execute(
                "SELECT generation, encrypted FROM targets WHERE id = ?", (target.id,)).fetchone()
        if encrypted is None:
            return generation, None
        try:
            record = json.loads(self.cipher().decrypt(encrypted))
            if record["binding"] != target.lock_key:
                raise ValueError
            return generation, record["session"]
        except (InvalidToken, UnicodeError, ValueError, KeyError, TypeError):
            raise Error("session_unreadable", "The stored session could not be verified. Log out locally and log in again.") from None

    def generation(self, target):
        with self.db() as db:
            return db.execute("SELECT generation FROM targets WHERE id = ?", (target.id,)).fetchone()[0]

    def save(self, target, generation, data, replace=False):
        encrypted = self.cipher(create=replace).encrypt(json.dumps({
            "binding": target.lock_key, "session": data
        }).encode())
        with self.db() as db:
            result = db.execute(
                "UPDATE targets SET encrypted = ?, generation = generation + ? WHERE id = ? AND generation = ?",
                (encrypted, int(replace), target.id, generation))
            if result.rowcount != 1:
                raise Error("session_changed", "Another login or logout changed this session. Check status and retry.")

    def logout(self, target):
        with self.locked(target.lock_key), self.db() as db:
            existed = db.execute("SELECT encrypted IS NOT NULL FROM targets WHERE id = ?",
                                 (target.id,)).fetchone()[0]
            db.execute("UPDATE targets SET encrypted = NULL, generation = generation + 1 WHERE id = ?",
                       (target.id,))
        return bool(existed)
