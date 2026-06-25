# -*- coding: utf-8 -*-
"""Pure Python policy evaluation logic.

Port of the C CheckPolicy/NormalizePath/IsSubpath logic from sandbox_hook.c.
Fully debuggable — add breakpoints, print statements, or logging anywhere.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Constants (must match sandbox_hook.h)
# ═══════════════════════════════════════════════════════════════════════════════

# Access flags for rules
ACCESS_DENY = 0x00
ACCESS_READ = 0x01
ACCESS_WRITE = 0x02
ACCESS_EXECUTE = 0x04
ACCESS_READ_EXECUTE = ACCESS_READ | ACCESS_EXECUTE
ACCESS_READ_WRITE = ACCESS_READ | ACCESS_WRITE
ACCESS_FULL = ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE

# Policy header flags
POLICY_FLAG_DENY_NETWORK = 0x01
POLICY_FLAG_ALLOW_READ_ALL = 0x02

# Violation types (for logging)
VIOLATION_READ = 0x0001
VIOLATION_WRITE = 0x0002
VIOLATION_DELETE = 0x0004
VIOLATION_EXECUTE = 0x0008
VIOLATION_NETWORK = 0x0010

# File access mask bits that imply write intent
_WRITE_MASKS = (
    0x0002 |   # FILE_WRITE_DATA
    0x0004 |   # FILE_APPEND_DATA
    0x0010 |   # FILE_WRITE_EA
    0x0100 |   # FILE_WRITE_ATTRIBUTES
    0x00010000 |  # DELETE
    0x0040 |   # FILE_DELETE_CHILD
    0x40000000    # GENERIC_WRITE
)

# File access mask bits that imply execute intent
_EXEC_MASKS = (
    0x0020 |      # FILE_EXECUTE
    0x20000000    # GENERIC_EXECUTE
)

# File access mask bits that imply delete intent
_DELETE_MASKS = (
    0x00010000 |  # DELETE
    0x0040        # FILE_DELETE_CHILD
)


# ═══════════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class PolicyRule:
    """A single policy rule (path prefix + access level)."""

    path: str         # Normalized: lowercase, backslash, no trailing slash
    path_len: int     # len(path), cached for performance
    access: int       # ACCESS_* bitmask
    is_deny: bool     # True for deny rules (always take precedence)


# ═══════════════════════════════════════════════════════════════════════════════
# PolicyChecker
# ═══════════════════════════════════════════════════════════════════════════════


class PolicyChecker:
    """Evaluates file access against sandbox policy rules.

    Thread-safe for read-only access (rules are immutable after __init__).
    """

    def __init__(self, policy_json: str):
        self.rules: List[PolicyRule] = []
        self.allow_read_all: bool = False
        self.deny_network: bool = False
        self._parse(policy_json)

    def _parse(self, policy_json: str) -> None:
        """Parse JSON policy into rule list."""
        policy = json.loads(policy_json)
        self.allow_read_all = policy.get("allow_read_all", False)
        self.deny_network = policy.get("deny_network", False)

        for rule_dict in policy.get("rules", []):
            path = self._normalize_rule_path(rule_dict["path"])
            access_str = rule_dict.get("access", "r")

            if access_str == "deny":
                access = ACCESS_DENY
                is_deny = True
            elif access_str == "rw":
                access = ACCESS_FULL
                is_deny = False
            elif access_str == "rx":
                access = ACCESS_READ_EXECUTE
                is_deny = False
            elif access_str == "r":
                access = ACCESS_READ
                is_deny = False
            else:
                logger.warning("Unknown access type %r, defaulting to read", access_str)
                access = ACCESS_READ
                is_deny = False

            self.rules.append(PolicyRule(
                path=path,
                path_len=len(path),
                access=access,
                is_deny=is_deny,
            ))

    @staticmethod
    def _normalize_rule_path(path: str) -> str:
        """Normalize a path from policy JSON (lowercase, backslash, strip trailing)."""
        path = path.lower().replace("/", "\\")
        if len(path) > 3 and path.endswith("\\"):
            path = path[:-1]
        return path

    def normalize_nt_path(self, raw_path: str) -> Optional[str]:
        """Normalize an NT kernel path to a comparable Win32 path.

        Handles:
          - \\??\\C:\\... → c:\\...
          - \\Device\\HarddiskVolumeN\\... → None (cannot resolve)
          - UNC paths pass through (lowercased)
          - Forward slashes → backslashes
          - Trailing backslash stripped (except root like c:\\)
        """
        if not raw_path:
            return None

        # Strip \\?\\ prefix (NT path format from NtCreateFile)
        if raw_path.startswith("\\??\\"):
            raw_path = raw_path[4:]
        elif raw_path.startswith("\\Device\\HarddiskVolume"):
            # Cannot resolve volume number to drive letter without
            # QueryDosDevice; skip policy check for these
            return None

        if not raw_path:
            return None

        # Normalize case and separators
        path = raw_path.lower().replace("/", "\\")

        # Strip trailing backslash (unless it's a root like "c:\\")
        if len(path) > 3 and path.endswith("\\"):
            path = path[:-1]

        return path

    def check(self, norm_path: str, desired_access: int) -> Tuple[bool, int]:
        """Check if a file access is allowed by the policy.

        Args:
            norm_path: Normalized path (from normalize_nt_path).
            desired_access: Windows ACCESS_MASK value.

        Returns:
            (allowed, violation_type) tuple.
            If allowed=True, violation_type is 0.
            If allowed=False, violation_type is one of VIOLATION_*.
        """
        path_len = len(norm_path)

        # Classify the access intent
        wants_write = bool(desired_access & _WRITE_MASKS)
        wants_exec = bool(desired_access & _EXEC_MASKS)
        wants_delete = bool(desired_access & _DELETE_MASKS)

        # Find best matching rule (longest prefix, deny always wins)
        best_idx = -1
        best_len = 0

        for i, rule in enumerate(self.rules):
            if self._is_subpath(norm_path, path_len, rule.path, rule.path_len):
                # Deny rules have absolute priority — return immediately
                if rule.is_deny:
                    vtype = self._classify_violation(
                        wants_write, wants_delete, wants_exec,
                    )
                    return (False, vtype)
                # Track longest matching allow rule
                if rule.path_len > best_len:
                    best_len = rule.path_len
                    best_idx = i

        # Apply the best matching allow rule
        if best_idx >= 0:
            allowed = self.rules[best_idx].access
            if wants_write and not (allowed & ACCESS_WRITE):
                return (False, VIOLATION_WRITE)
            if wants_delete and not (allowed & ACCESS_WRITE):
                return (False, VIOLATION_WRITE)
            if wants_exec and not (allowed & ACCESS_EXECUTE):
                return (False, VIOLATION_EXECUTE)
            return (True, 0)

        # No rule matched: apply default policy
        if self.allow_read_all:
            if wants_write or wants_delete:
                return (False, VIOLATION_WRITE)
            return (True, 0)

        # Strict mode: deny everything not explicitly allowed
        vtype = VIOLATION_WRITE if wants_write else VIOLATION_READ
        return (False, vtype)

    @staticmethod
    def _is_subpath(
        path: str, path_len: int, rule: str, rule_len: int,
    ) -> bool:
        """Check if path is equal to or under rule path (prefix + boundary)."""
        if path_len < rule_len:
            return False
        if path[:rule_len] != rule:
            return False
        if path_len == rule_len:
            return True
        # Must have a backslash separator at the boundary
        return path[rule_len] == "\\"

    @staticmethod
    def _classify_violation(
        wants_write: bool, wants_delete: bool, wants_exec: bool,
    ) -> int:
        """Determine violation type for deny rules."""
        if wants_write:
            return VIOLATION_WRITE
        if wants_delete:
            return VIOLATION_DELETE
        if wants_exec:
            return VIOLATION_EXECUTE
        return VIOLATION_READ
