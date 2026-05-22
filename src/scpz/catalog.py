"""AWS IAM action catalog for semantic-safe wildcard compression.

The catalog maps IAM service prefixes (e.g. ``"iam"``) to the complete set of
known action names for that service (e.g. ``["CreateRole", "DeleteRole", ...]``).

It is used by the ``actionCompress`` pass to determine whether a verb-level
wildcard like ``iam:Delete*`` can be emitted safely in conservative mode: if
every catalog action that starts with ``Delete`` is already present in the
statement, emitting the wildcard adds no new permissions.

Usage::

    catalog = ActionCatalog.load(config.spec.catalog)
    if catalog.covers("iam", "Delete", frozenset(["DeleteRole", "DeleteUser"])):
        # safe to emit iam:Delete*
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path  # noqa: TC003 — used at runtime in from_file()
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from scpz.config import CatalogConfig

# Package-relative path to the bundled catalog file
_DATA_PACKAGE = "scpz.data"
_CATALOG_FILE = "aws_actions.json"


class ActionCatalog:
    """Immutable mapping of IAM service prefix → frozenset of action names.

    Instantiate via :meth:`load` or :meth:`empty`.  Direct construction is
    supported for testing: pass a plain ``dict[str, list[str]]``.
    """

    def __init__(self, data: dict[str, frozenset[str]]) -> None:
        self._data = data

    # ── Factory methods ───────────────────────────────────────────────

    @classmethod
    def empty(cls) -> ActionCatalog:
        """Return a catalog with no data (disables catalog-aware compression)."""
        return cls({})

    @classmethod
    def from_dict(cls, raw: dict[str, list[str]]) -> ActionCatalog:
        """Build a catalog from a plain mapping of service → action-name list."""
        return cls({svc: frozenset(names) for svc, names in raw.items()})

    @classmethod
    def from_file(cls, path: Path) -> ActionCatalog:
        """Load a catalog from a JSON file on disk."""
        text = path.read_text(encoding="utf-8")
        raw: dict[str, list[str]] = json.loads(text)
        return cls.from_dict(raw)

    @classmethod
    def bundled(cls) -> ActionCatalog:
        """Load the catalog shipped with the scpz package."""
        pkg = resources.files(_DATA_PACKAGE)
        text = (pkg / _CATALOG_FILE).read_text(encoding="utf-8")
        raw: dict[str, list[str]] = json.loads(text)
        return cls.from_dict(raw)

    @classmethod
    def load(cls, cfg: CatalogConfig) -> ActionCatalog:
        """Dispatch on ``cfg.source`` and return the appropriate catalog."""
        if cfg.source == "none":
            return cls.empty()
        if cfg.source == "file":
            if cfg.path is None:
                msg = "catalog.path is required when catalog.source is 'file'"
                raise ValueError(msg)
            return cls.from_file(cfg.path)
        return cls.bundled()

    # ── Query interface ───────────────────────────────────────────────

    def is_empty(self) -> bool:
        """Return True if the catalog contains no data."""
        return not self._data

    def get_service(self, service: str) -> frozenset[str]:
        """Return the frozenset of known action names for *service*, or empty."""
        return self._data.get(service, frozenset())

    def iter_full_actions(self) -> Iterator[str]:
        """Yield every ``service:name`` string in this catalog (lowercase service prefix)."""
        for service, names in self._data.items():
            for name in names:
                yield f"{service.lower()}:{name}"

    def literal_action_known(
        self,
        service: str,
        action_suffix: str,
    ) -> bool | None:
        """Return whether *action_suffix* is a known literal action for *service*.

        *service* should be lower-case (e.g. ``"iam"``). *action_suffix* is the
        portion after the colon in ``service:Verb`` (e.g. ``"DeleteRole"``).

        Returns
        -------
        ``True``
            The action appears in this catalog for the service.
        ``False``
            The service is catalogued (has at least one known action) but this
            literal name is not listed — useful for typo detection.
        ``None``
            No verdict: empty catalog, *action_suffix* contains a wildcard
            character (``*`` / ``?``), or the service has no entries in this
            catalog (cannot validate literals).
        """
        if self.is_empty():
            return None
        if "*" in action_suffix or "?" in action_suffix:
            return None
        known = self.get_service(service)
        if not known:
            return None
        return action_suffix in known

    def all_full_actions(self) -> frozenset[str]:
        """Return every ``service:name`` pair in the catalog (lowercase service prefix)."""
        atoms: set[str] = set()
        for service, names in self._data.items():
            for name in names:
                atoms.add(f"{service.lower()}:{name}")
        return frozenset(atoms)

    def covers(
        self,
        service: str,
        verb: str,
        candidate_names: frozenset[str],
    ) -> bool:
        """Return True when the catalog confirms full wildcard coverage.

        A verb-level wildcard (``service:Verb*``) is safe to emit iff every
        action in the catalog for *service* that starts with *verb* is already
        present in *candidate_names*.  An empty catalog always returns False.

        Parameters
        ----------
        service:
            IAM service prefix, e.g. ``"iam"``.
        verb:
            Verb portion of the action name, e.g. ``"Delete"``.
        candidate_names:
            The action names (without service prefix) currently in the
            statement for *service*.
        """
        if self.is_empty():
            return False
        known = self.get_service(service)
        if not known:
            return False
        matching = frozenset(name for name in known if name.startswith(verb))
        if not matching:
            # Verb not in catalog at all — don't trust that the wildcard is safe
            return False
        return matching.issubset(candidate_names)
