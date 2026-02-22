"""Technology fingerprinting tool."""

import asyncio
import logging
import re

import httpx

logger = logging.getLogger(__name__)

# Header-based fingerprints
HEADER_FINGERPRINTS = {
    "server": lambda v: v,  # nginx/1.24.0, Apache/2.4.52
    "x-powered-by": lambda v: v,  # Express, PHP/8.1.0, ASP.NET
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-aspnetmvc-version": lambda v: f"ASP.NET MVC {v}",
    "x-drupal-cache": lambda v: "Drupal",
    "x-generator": lambda v: v,  # WordPress, Drupal, etc.
    "x-shopify-stage": lambda v: "Shopify",
    "x-wix-request-id": lambda v: "Wix",
    "x-squarespace-vary": lambda v: "Squarespace",
}

# HTML content fingerprints (regex pattern, tech name)
HTML_FINGERPRINTS = [
    # JavaScript frameworks
    (r'<script[^>]*src="[^"]*react[^"]*"', "React"),
    (r'<script[^>]*src="[^"]*angular[^"]*"', "Angular"),
    (r'<script[^>]*src="[^"]*vue[^"]*"', "Vue.js"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"__NUXT__", "Nuxt.js"),
    (r'<script[^>]*src="[^"]*svelte[^"]*"', "Svelte"),
    (r'<script[^>]*src="[^"]*ember[^"]*"', "Ember.js"),
    (r'<script[^>]*src="[^"]*backbone[^"]*"', "Backbone.js"),
    (r'<script[^>]*src="[^"]*jquery[^"]*"', "jQuery"),
    (r'<script[^>]*src="[^"]*bootstrap[^"]*"', "Bootstrap"),
    (r'<link[^>]*href="[^"]*bootstrap[^"]*"', "Bootstrap"),
    # CMS
    (r'<meta[^>]*name="generator"[^>]*content="WordPress[^"]*"', "WordPress"),
    (r"/wp-content/", "WordPress"),
    (r"/wp-includes/", "WordPress"),
    (r'<meta[^>]*name="generator"[^>]*content="Drupal[^"]*"', "Drupal"),
    (r'<meta[^>]*name="generator"[^>]*content="Joomla[^"]*"', "Joomla"),
    (r"Powered by.*Shopify", "Shopify"),
    # Server-side
    (r"\.php", "PHP"),
    (r"\.aspx", "ASP.NET"),
    (r"\.jsp", "Java/JSP"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"__RequestVerificationToken", "ASP.NET MVC"),
    (r"laravel_session", "Laravel"),
    (r"PHPSESSID", "PHP"),
    # Analytics & tools
    (r"google-analytics\.com", "Google Analytics"),
    (r"gtag\(", "Google Tag Manager"),
    (r"googletagmanager\.com", "Google Tag Manager"),
    (r"hotjar\.com", "Hotjar"),
    (r"sentry\.io", "Sentry"),
    (r"cdn\.segment\.com", "Segment"),
]

# Cookie-based fingerprints
COOKIE_FINGERPRINTS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "_rails_session": "Ruby on Rails",
    "connect.sid": "Express.js",
}


async def fingerprint_tech(url: str, timeout: float = 10.0) -> list[str]:
    """
    Fingerprint technologies used by a web application.

    Analyzes:
    - HTTP response headers (Server, X-Powered-By, etc.)
    - HTML content for framework signatures
    - Cookies for session identifiers

    Args:
        url: URL to fingerprint
        timeout: Request timeout in seconds

    Returns:
        List of identified technologies (deduplicated)
    """
    logger.info(f"Fingerprinting technologies for {url}")

    technologies: set[str] = set()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.get(url)

            # Analyze headers
            for header_name, extractor in HEADER_FINGERPRINTS.items():
                value = response.headers.get(header_name)
                if value:
                    tech = extractor(value)
                    if tech:
                        technologies.add(tech)

            # Analyze cookies
            for cookie_name, tech in COOKIE_FINGERPRINTS.items():
                if cookie_name in response.cookies:
                    technologies.add(tech)

            # Check Set-Cookie header for session cookies
            set_cookie = response.headers.get("set-cookie", "")
            for cookie_name, tech in COOKIE_FINGERPRINTS.items():
                if cookie_name in set_cookie:
                    technologies.add(tech)

            # Analyze HTML content
            content = response.text
            for pattern, tech in HTML_FINGERPRINTS:
                if re.search(pattern, content, re.IGNORECASE):
                    technologies.add(tech)

            # Extract version info from common patterns
            # nginx/1.24.0 -> already captured by server header
            # Look for version meta tags
            generator_match = re.search(
                r'<meta[^>]*name="generator"[^>]*content="([^"]+)"',
                content,
                re.IGNORECASE,
            )
            if generator_match:
                technologies.add(generator_match.group(1))

    except httpx.TimeoutException:
        logger.warning(f"Timeout fingerprinting {url}")
    except httpx.RequestError as e:
        logger.warning(f"Request error fingerprinting {url}: {e}")
    except Exception as e:
        logger.error(f"Error fingerprinting {url}: {e}")

    result = sorted(technologies)
    logger.info(f"Found {len(result)} technologies for {url}: {result}")
    return result


async def fingerprint_from_services(services: list[dict]) -> list[str]:
    """
    Extract technology info from nmap service detection.

    Args:
        services: List of ServiceInfo dicts with port, service, version

    Returns:
        List of identified technologies
    """
    technologies: set[str] = set()

    for svc in services:
        service = svc.get("service", "")
        version = svc.get("version")

        if service and version:
            technologies.add(f"{service}/{version}")
        elif service:
            technologies.add(service)

    return sorted(technologies)
