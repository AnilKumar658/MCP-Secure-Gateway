"""
servers/
Exposes all mock MCP server instances under a single registry so the
gateway's mcp_backend can look them up by name.
"""
from servers.git_server  import GitServer
from servers.file_server import FileServer
from servers.mail_server import MailServer
from servers.web_server  import WebServer
from servers.code_server import CodeServer

REGISTRY: dict[str, object] = {
    "git":  GitServer(),
    "file": FileServer(),
    "mail": MailServer(),
    "web":  WebServer(),
    "code": CodeServer(),
}

__all__ = ["REGISTRY", "GitServer", "FileServer", "MailServer", "WebServer", "CodeServer"]
