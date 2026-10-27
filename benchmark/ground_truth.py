"""Known-vulnerable endpoints per target, used to compute recall and
precision in metrics.py (design doc Section 7). Fill these in against the
actual running container before trusting the numbers -- they're starting
points, not verified ground truth, until you've confirmed each entry by hand
against your own DVWA/Juice Shop/WebGoat instance.

Each entry: (vuln_type, url_substring_or_path_template, param_name_or_None).
A ProbeDAST finding "hits" a ground-truth entry if its vuln_type matches and
its endpoint URL contains the substring (param match is checked when given).
"""

DVWA_GROUND_TRUTH = [
    ("xss", "/vulnerabilities/xss_r/", "name"),
    ("xss", "/vulnerabilities/xss_s/", "txtName"),
    ("sqli", "/vulnerabilities/sqli/", "id"),
    ("sqli", "/vulnerabilities/sqli_blind/", "id"),
    ("path_traversal", "/vulnerabilities/fi/", "page"),
    ("idor", "/vulnerabilities/csrf/", None),  # DVWA doesn't have a clean IDOR module; adjust per version
]

JUICESHOP_GROUND_TRUTH = [
    ("xss", "/rest/products/search", "q"),
    ("sqli", "/rest/user/login", "email"),
    ("idor", "/rest/basket/", None),
    ("idor", "/rest/user/", None),
]

WEBGOAT_GROUND_TRUTH = [
    ("xss", "/WebGoat/CrossSiteScripting/", None),
    ("sqli", "/WebGoat/SqlInjection/", None),
    ("path_traversal", "/WebGoat/PathTraversal/", None),
    ("idor", "/WebGoat/IDOR/", None),
]

ALL = {
    "dvwa": DVWA_GROUND_TRUTH,
    "juiceshop": JUICESHOP_GROUND_TRUTH,
    "webgoat": WEBGOAT_GROUND_TRUTH,
}
