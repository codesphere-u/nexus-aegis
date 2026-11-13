"""FastAPI ASGI / Vercel entrypoint for NexusAegis."""

from __future__ import annotations

from fastapi import FastAPI, Request, Response

from nexus_aegis import __version__
from nexus_aegis.http_server import (
    BadRequestError,
    NexusAegisHTTPApp,
    PayloadTooLargeError,
    parse_content_length,
)


async def _read_bounded_body(request: Request, max_body_bytes: int) -> bytes:
    content_len = parse_content_length(request.headers)
    if content_len is not None and content_len > max_body_bytes:
        raise PayloadTooLargeError(f"Request body exceeds limit of {max_body_bytes} bytes.")

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_body_bytes:
            raise PayloadTooLargeError(f"Request body exceeds limit of {max_body_bytes} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


def create_fastapi_app(*, max_body_bytes: int | None = None) -> FastAPI:
    """Build a FastAPI ASGI app backed by NexusAegisHTTPApp."""
    core_app = NexusAegisHTTPApp(max_body_bytes=max_body_bytes)
    fastapi_app = FastAPI(
        title="NexusAegis PCAE Kernel & MCP Server",
        version=__version__,
        description=(
            "Proof-Carrying Autonomous Agent Kernel, 7-Gate Deterministic Pipeline, "
            "and RFC 6962 Selective-Disclosure Merkle Attestation Engine."
        ),
    )

    @fastapi_app.api_route(
        "/",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    @fastapi_app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        include_in_schema=False,
    )
    async def dispatch(request: Request, full_path: str = "") -> Response:
        _ = full_path
        target = f"{request.url.path}?{request.url.query}" if request.url.query else request.url.path
        try:
            body = await _read_bounded_body(request, core_app.max_body_bytes)
        except PayloadTooLargeError:
            http_resp = core_app.handle_http(
                request.method,
                target,
                request.headers,
                b"x" * (core_app.max_body_bytes + 1),
            )
            headers = {k: v for k, v in http_resp.headers.items() if k.lower() != "content-length"}
            return Response(content=http_resp.body, status_code=http_resp.status, headers=headers)
        except BadRequestError:
            http_resp = core_app.handle_http(
                request.method,
                target,
                {"content-length": "-1", **dict(request.headers)},
                b"",
            )
            headers = {k: v for k, v in http_resp.headers.items() if k.lower() != "content-length"}
            return Response(content=http_resp.body, status_code=http_resp.status, headers=headers)

        http_resp = core_app.handle_http(request.method, target, request.headers, body)
        headers = {k: v for k, v in http_resp.headers.items() if k.lower() != "content-length"}
        return Response(content=http_resp.body, status_code=http_resp.status, headers=headers)

    return fastapi_app


app = create_fastapi_app()
