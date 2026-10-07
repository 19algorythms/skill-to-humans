#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api.py — HTTP wrapper for the skill-to-humans Decode Engine v1.3.

Thin layer, zero detection logic: the engine does the work, this file only
carries HTTP plus the operational guards added by Audit 1
(mistral-medium-3-5, 2026-10): request size caps, binary-content refusal,
a small in-memory rate limiter and request logging (no payload content is
ever logged). Start command: uvicorn api:app --host 0.0.0.0 --port $PORT

Endpoints:
  GET  /         service info (a root route is required by most PaaS)
  GET  /health   keepalive probe
  POST /reveal   reveal hidden content — multipart file upload, form field
                 "content", or JSON body {"content": "...", "filename": "..."}

Philosophy: we do not judge. We show what the agent would read.
"""

import logging
import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import JSONResponse

import skill_to_humans as engine

VERSION = "1.3"

# Audit 1 (anti-DoS): the API never accepts more than the engine will
# process, and each client IP gets a bounded request rate.
MAX_CONTENT_SIZE = engine.MAX_INPUT_SIZE   # 100 000 chars, same bound as engine
RATE_LIMIT = 30                            # requests per window per IP
RATE_WINDOW = 60.0                         # seconds

logger = logging.getLogger("skill-to-humans")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(
    title="skill-to-humans",
    version=VERSION,
    description="Reveal hidden content in AI skill files. " + engine.CONTRACT_PHRASE,
)

# In-memory sliding window per client. Deliberately simple: this wrapper
# runs as a single process; if you front it with several replicas, move the
# limiter to the proxy (or to Redis) instead.
_hits = defaultdict(deque)


def _client_ip(request: Request) -> str:
    """Behind RapidAPI (and Cloudflare) every request arrives from the same
    proxy IP — key the limiter on the original client carried in
    X-Forwarded-For, else one abusive user throttles every customer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def _rate_limited(client: str) -> bool:
    now = time.monotonic()
    window = _hits[client]
    while window and now - window[0] > RATE_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        return True
    window.append(now)
    return False


def _looks_binary(raw: bytes) -> bool:
    """Heuristic: refuse payloads that are clearly not text (binaries,
    archives, images). Text control chars (tab, LF, CR) stay acceptable."""
    if not raw:
        return False
    sample = raw[:4096]
    suspicious = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20))
    return suspicious * 20 > len(sample)  # >5% control bytes -> binary


@app.get("/")
def root():
    return {
        "service": "skill-to-humans",
        "version": VERSION,
        "docs": "/docs",
        "philosophy": engine.CONTRACT_PHRASE,
        "not_covered": engine.NOT_COVERED,
    }


@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION, "engine": "loaded"}


@app.post("/reveal")
async def reveal(
    request: Request,
    file: UploadFile | None = None,
    content: str | None = Form(None),
):
    """Reveal the hidden content of a skill file. Accepts, in priority order:
    multipart file upload, form field 'content', or JSON body."""
    client = _client_ip(request)
    if _rate_limited(client):
        logger.warning("rate limited client=%s", client)
        return JSONResponse(status_code=429,
                            content={"error": "rate limit exceeded"})

    name = "upload"

    if file is not None:
        raw = await file.read()
        if len(raw) > MAX_CONTENT_SIZE:
            return JSONResponse(status_code=413,
                                content={"error": "file too large "
                                                 "(max %d bytes)" % MAX_CONTENT_SIZE})
        if _looks_binary(raw):
            return JSONResponse(status_code=415,
                                content={"error": "binary content is not "
                                                 "supported, send text"})
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        name = file.filename or name
    elif content is not None:
        text = content
    else:
        try:
            body = await request.json()
        except Exception:
            body = None
        if not body or "content" not in body:
            return JSONResponse(
                status_code=400,
                content={"error": "send a multipart file, form field 'content', "
                                  "or JSON body {'content': '...'} "},
            )
        text = body["content"]
        name = body.get("filename", name)

    if len(text) > MAX_CONTENT_SIZE:
        return JSONResponse(status_code=413,
                            content={"error": "content too large "
                                             "(max %d characters)" % MAX_CONTENT_SIZE})

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        rendered, ctx = engine.render_text(text)
    except ValueError as e:  # engine's own bound, kept as a second fence
        return JSONResponse(status_code=413, content={"error": str(e)})

    techniques = sum(ctx.counts.values())
    logger.info("reveal client=%s file=%s chars=%d techniques=%d",
                client, name, len(text), techniques)
    return {
        "file": name,
        "rendered": rendered,
        "summary": engine.build_summary(name, ctx, []),
        "techniques_found": techniques,
        "not_covered": engine.NOT_COVERED,
        "philosophy": engine.CONTRACT_PHRASE,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
