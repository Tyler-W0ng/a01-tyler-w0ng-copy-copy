"""Agent-side neutral-package filter.

Name -> CPE resolution lives on the MCP server (its `resolve_name` tool). The
only naming logic left in the agent is this filter: which extracted candidates
are OS/distro plumbing the grader ignores, and so should not be reported or
even resolved.
"""

import re

# OS / distro base packages, which the grader ignores. Kept deliberately
# CONSERVATIVE: only unambiguous operating-system plumbing that is never a
# scored target. Application libraries that carry CVEs (libxml2, openssl,
# sudo, krb5, gnutls, pcre, expat, ...) are NOT here - dropping one would lose
# a real product, and the grader already ignores true OS packages on its own.
NEUTRAL = {
    "coreutils", "systemd", "dpkg", "apt", "musl", "libc", "libc-utils",
    "dash", "base-files", "base-passwd", "adduser", "gzip", "tar", "sed",
    "grep", "gawk", "mawk", "findutils", "util-linux", "login", "passwd",
    "perl-base", "debconf", "alpine-baselayout", "alpine-keys", "apk-tools",
    "busybox", "ca-certificates", "e2fsprogs", "hostname",
    "init-system-helpers", "tzdata", "mount", "procps", "sysvinit-utils",
    # RPM / RHEL base plumbing (package managers and distro scaffolding only)
    "basesystem", "filesystem", "setup", "kmod", "shadow-utils",
    "yum", "rpm", "dnf", "cronie", "rsyslog",
    # The OS kernel itself is the operating system, which the grader ignores.
    # A uname banner ("system=Linux/5.4.0-150-generic") otherwise resolves to
    # linux:linux_kernel and dumps its ~1000 CVEs into the output.
    "linux", "linux_kernel", "linux kernel",
}

# Sub-package suffixes to strip so a package name matches its base:
# "openssh-server" -> "openssh", "sqlite-libs" -> "sqlite".
_SUBPKG = re.compile(
    r"-(lib|libs|server|client|clients|common|dev|devel|bin|doc|docs|data|"
    r"core|utils|util|tools|mod|module|agent)$")


def _base(name: str) -> str:
    n = name.strip().lower()
    return _SUBPKG.sub("", n) or n


def is_neutral(name: str) -> bool:
    n = name.strip().lower()
    return n in NEUTRAL or _base(n) in NEUTRAL
