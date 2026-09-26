"""URL normalization (raw_url + canonical_url) + API classification."""
from urllib.parse import urlparse, urlunparse

API_PATTERNS = ["/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/", "/swagger", "/openapi.json", "/v1/", "/v2/", "/wp-json/"]


def canonicalize_url(raw: str) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
    except Exception:
        return None
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return None
    port = p.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if (not port or port == default) else f"{host}:{port}"
    path = p.path or "/"
    query = p.query  # keep useful query params
    return urlunparse((scheme, netloc, path, "", query, ""))


def classify_api(url: str) -> tuple[bool, str, list]:
    low = url.lower()
    for pat in API_PATTERNS:
        if pat in low:
            api_type = "GraphQL" if "graphql" in low else ("OpenAPI/Swagger" if ("swagger" in low or "openapi" in low) else "REST")
            auth_hints = [h for h in ("auth", "login", "token", "admin", "internal") if h in low]
            return True, api_type, auth_hints
    return False, "", []
