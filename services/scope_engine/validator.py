"""Scope Validator — mandatory gate before ANY active operation."""
import ipaddress


def _matches_domain(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def validate_host(target, host: str, scope_rules) -> tuple[bool, str]:
    """Check host against target scope rules. Returns (allowed, reason)."""
    host = (host or "").lower().strip().rstrip(".")
    allows = [r.value for r in scope_rules if r.rule_type == "allow_domain"]
    excludes = [r.value for r in scope_rules if r.rule_type == "exclude_host"]
    for pat in excludes:
        if _matches_domain(host, pat):
            return False, f"excluded host {pat}"
    if allows:
        for pat in allows:
            if _matches_domain(host, pat):
                return True, "allowed"
        # default: subdomains of the root domain are allowed
        if host == target.root_domain or host.endswith("." + target.root_domain):
            return True, "allowed (root domain)"
        return False, "not in allowed domains"
    # no explicit allow rules: root domain + subdomains allowed
    if host == target.root_domain or host.endswith("." + target.root_domain):
        return True, "allowed (root domain)"
    return False, "outside root domain"


def validate_ip(target, ip: str, scope_rules) -> tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "invalid ip"
    for r in scope_rules:
        if r.rule_type == "exclude_ip":
            try:
                if addr in ipaddress.ip_network(r.value, strict=False):
                    return False, f"excluded ip {r.value}"
            except ValueError:
                continue
    allows = [r.value for r in scope_rules if r.rule_type == "allow_ip"]
    if allows:
        for net in allows:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True, "allowed"
            except ValueError:
                continue
        return False, "not in allowed ips"
    return True, "allowed"


def scope_allows_scan(target, scope_rules) -> tuple[bool, str]:
    if target.status != target.STATUS_ACTIVE:
        return False, f"target status {target.status}"
    if not target.is_scannable:
        return False, "authorization expired or target not active"
    return True, "ok"
