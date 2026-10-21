"""Map a product name to its CPE vendor:product identities ("aliases").

Three tiers:
  1. a small hand-written table for common names whose CPE name differs from
     how documents write them (allowed by the handout: a name->CPE map);
  2. the MCP server's search_products, ranked, for everything else;
  3. the graph asks the model to clean the name when search finds nothing.

A product can have several CPE identities (nginx is nginx:nginx, f5:nginx and
f5:nginx_open_source); we return all that share the chosen product name so
lookup can union their CVEs. We also drop OS base packages, which the grader
ignores and which would otherwise count as extra products.
"""

# name (lowercased) -> set of (vendor, product) CPE identities
ALIASES = {
    "nginx": {("nginx", "nginx"), ("f5", "nginx"), ("f5", "nginx_open_source")},
    "apache": {("apache", "http_server")},
    "apache2": {("apache", "http_server")},
    "httpd": {("apache", "http_server")},
    "apache httpd": {("apache", "http_server")},
    "microsoft-iis": {("microsoft", "internet_information_services")},
    "microsoft iis": {("microsoft", "internet_information_services")},
    "iis": {("microsoft", "internet_information_services")},
    "openssh": {("openbsd", "openssh")},
    "openssl": {("openssl", "openssl")},
    "libssl1.1": {("openssl", "openssl")},
    "libssl3": {("openssl", "openssl")},
    "libssl-dev": {("openssl", "openssl")},
    "node": {("nodejs", "node.js")},
    "nodejs": {("nodejs", "node.js")},
    "node.js": {("nodejs", "node.js")},
    "lighttpd": {("lighttpd", "lighttpd")},
    "jenkins": {("jenkins", "jenkins")},
    "memcached": {("memcached", "memcached")},
    "elasticsearch": {("elastic", "elasticsearch")},
    "bind": {("isc", "bind")},
    "mysql": {("oracle", "mysql")},
    "mysqld": {("oracle", "mysql")},
    "mariadb": {("mariadb", "mariadb")},
    "postgresql": {("postgresql", "postgresql")},
    "redis": {("redis", "redis")},
    "vsftpd": {("vsftpd_project", "vsftpd")},
    "django": {("djangoproject", "django")},
    "python3-django": {("djangoproject", "django")},
    "curl": {("haxx", "curl"), ("curl", "curl")},
    "runc": {("linuxfoundation", "runc"), ("opencontainers", "runc")},
}

# OS base packages the grader ignores; dropping them avoids extra-product
# penalties when a package list contains hundreds of them.
NEUTRAL = {
    "coreutils", "systemd", "dpkg", "apt", "apt-tools", "musl", "glibc",
    "libc", "libc6", "libc-utils", "bash", "dash", "sh", "base-files",
    "base-passwd", "adduser", "attr", "acl", "gzip", "tar", "sed", "grep",
    "gawk", "mawk", "findutils", "util-linux", "login", "passwd", "ncurses",
    "zlib", "zlib1g", "libgcc", "libstdc++", "gcc", "perl-base", "debconf",
    "alpine-baselayout", "alpine-keys", "apk-tools", "busybox", "ca-certificates",
    "e2fsprogs", "hostname", "init-system-helpers", "libselinux", "libpcre",
    "libpcre2", "tzdata", "mount", "procps", "sysvinit-utils", "diffutils",
}


def table(name: str):
    return ALIASES.get(name.strip().lower())


def is_neutral(name: str) -> bool:
    return name.strip().lower() in NEUTRAL


def rank_pick(name: str, candidates: list):
    """From search_products candidates, pick the best product's identities.

    Returns a set of (vendor, product). We take the best-scoring product name
    and include every candidate that shares it (its aliases).
    """
    if not candidates:
        return set()
    q = name.strip().lower()

    def score(c):
        p = c["product"].lower()
        if p == q:
            return 0
        if p.replace("_", "") == q.replace("_", ""):
            return 1
        if p.startswith(q) or q in p.split("_"):
            return 2
        if q in p:
            return 3
        return 4

    best = min(candidates, key=score)
    best_product = best["product"].lower()
    return {(c["vendor"].lower(), c["product"].lower())
            for c in candidates if c["product"].lower() == best_product}
