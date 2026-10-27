from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LoginRecipe:
    login_url: str
    username_field: str = "username"
    password_field: str = "password"
    users: dict = field(default_factory=dict)          # role -> {"username": .., "password": ..}
    extra_fields: dict = field(default_factory=dict)   # e.g. {"Login": "Login"} for a submit button
    success_indicator: str = "Logout"                  # text/element present only when logged in
    check_url: str = ""                                # authenticated page for the session health probe
    owned_markers: dict = field(default_factory=dict)  # role -> [strings identifying that role's own data]


@dataclass
class Config:
    target: str
    scope_hosts: list = field(default_factory=list)
    scope_paths: list = field(default_factory=lambda: ["/"])
    login: Optional[LoginRecipe] = None
    crawl_role: str = "A"
    safe_mode: bool = True             # never issue state-changing requests against discovered endpoints
    verify: bool = True
    verify_rounds: int = 3
    detectors: Optional[list] = None   # None = run every registered detector
    max_depth: int = 5
    max_endpoints: int = 500
    max_pages: int = 1000
    max_bytes: int = 1_000_000
    max_requests: Optional[int] = None
    rps: float = 10.0
    burst: int = 10
    workers: int = 8
    crawl_workers: int = 4
    time_delay: float = 3.0
    time_samples: int = 5
    xss_browser: str = "auto"          # off | auto | require
    js_fallback: bool = False
    base_cookies: dict = field(default_factory=dict)
    db_path: str = "probedast.db"
    db_url: Optional[str] = None       # postgresql://... switches the store to PostgreSQL
    redis_url: Optional[str] = None
    amqp_url: Optional[str] = None
    insecure_tls: bool = False
    debug: bool = False        # print tracebacks from failed jobs instead of swallowing them

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        d = dict(d)
        login = d.pop("login", None)
        cfg = cls(**d)
        if login:
            cfg.login = LoginRecipe(**login)
        return cfg

    @classmethod
    def from_file(cls, path: str) -> "Config":
        with open(path) as f:
            return cls.from_dict(json.load(f))
