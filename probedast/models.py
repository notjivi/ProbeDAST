from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RawResponse:
    status: int
    headers: dict                      # lower-cased header names -> value
    body: str
    elapsed: float                     # seconds, request start to body end
    url: str
    set_cookies: list = field(default_factory=list)
    truncated: bool = False

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


@dataclass
class Param:
    name: str
    location: str                      # query | body | path | header | cookie
    sample: str = ""
    type: str = "text"                 # int | uuid | email | boolean | text
    attackable: bool = True

    def to_dict(self):
        return dict(self.__dict__)


@dataclass
class Endpoint:
    method: str
    url: str                           # base URL, no query string
    path_template: str
    params: list
    signature: str
    auth_required: bool = False
    state_changing: bool = False
    role: Optional[str] = None
    scan_id: str = ""
    endpoint_id: str = ""

    def to_dict(self):
        return {
            "endpoint_id": self.endpoint_id, "method": self.method, "url": self.url,
            "path_template": self.path_template, "signature": self.signature,
            "params": [p.to_dict() for p in self.params],
            "auth_required": self.auth_required, "state_changing": self.state_changing,
            "role": self.role,
        }


@dataclass
class Candidate:
    vuln_type: str                     # xss | sqli | path_traversal | idor | header | cookie | cors
    technique: str                     # reflected | error-based | boolean | time-based | two-session | passive
    detector: str
    endpoint: Endpoint
    param: Optional[Param]
    severity: str
    evidence: dict
    context: dict = field(default_factory=dict)   # inputs verify_round needs to replay the probe


@dataclass
class Job:
    job_id: str
    scan_id: str
    endpoint_id: str
    param: str
    detector: str

    def to_dict(self):
        return dict(self.__dict__)


def new_id() -> str:
    return str(uuid.uuid4())
