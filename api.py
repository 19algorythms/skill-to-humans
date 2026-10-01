#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api.py — HTTP wrapper for the skill-to-humans Decode Engine v1.2.

Thin layer, zero logic: the engine does the work, this file only carries
HTTP. Start command: uvicorn api:app --host 0.0.0.0 --port $PORT

Endpoints:
  GET  /         service info (a root route is required by most PaaS)
  GET  /health   keepalive probe
  POST /reveal   reveal hidden content — multipart file upload, form field
                 "content", or JSON body {"content": "...", "filename": "..."}

Philosophy: we do not judge. We show what the agent would read.
"""

import os

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import JSONResponse

import skill_to_humans as engine

VERSION = "1.2"

app = FastAPI(
    title="skill-to-humans",
    version=VERSION,
    description="Reveal hidden content in AI skill files. " + engine.CONTRACT_PHRASE,
)


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
    name = "upload"

    if file is not None:
        raw = await file.read()
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

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    rendered, ctx = engine.render_text(text)
    return {
        "file": name,
        "rendered": rendered,
        "summary": engine.build_summary(name, ctx, []),
        "techniques_found": sum(ctx.counts.values()),
        "not_covered": engine.NOT_COVERED,
        "philosophy": engine.CONTRACT_PHRASE,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
