import socket
import pytest

from tests.vuln_app import start as start_vuln_app


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def vuln_app_base_url():
    port = _free_port()
    start_vuln_app(port)
    return f"http://127.0.0.1:{port}"
