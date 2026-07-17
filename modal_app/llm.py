"""
Qwen 2.5 7B on Modal GPU (T4), scale-to-zero, exposed as an Ollama-compatible
HTTP endpoint so analysis/ollama_client.py works unchanged (it POSTs
{OLLAMA_URL}/api/chat). The model is baked into the image at build (no runtime
download / air-gapped-at-runtime, same discipline as the scanner tools).

Wire the backend to it:
    OLLAMA_URL=https://<workspace>--onus-llm-ollama-api.modal.run
    OLLAMA_AUTH_TOKEN=<the token below>

Deploy:  modal deploy modal_app/llm.py
Auth (REQUIRED — the endpoint refuses to serve requests without it):
    modal secret create onus-llm-auth OLLAMA_AUTH_TOKEN=$(openssl rand -hex 24)
"""
import os
import subprocess
import time

import modal

MODEL = "qwen2.5:7b"

# Install Ollama, then bake the model into the image (start server, pull, stop).
llm_image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl", "zstd")  # zstd: the ollama install.sh extractor needs it
    .run_commands("curl -fsSL https://ollama.com/install.sh | sh")
    .pip_install("fastapi[standard]==0.115.*", "httpx==0.27.*")
    .run_commands(
        # Start the server just long enough to pull the model into the image layer.
        f"bash -c 'ollama serve & sleep 8 && ollama pull {MODEL} && sleep 2'",
    )
    .env({"OLLAMA_HOST": "0.0.0.0:11434"})
)

app = modal.App("onus-llm")

# Auth is mandatory: `modal secret create onus-llm-auth OLLAMA_AUTH_TOKEN=...`.
# If the secret is absent the endpoint still deploys but every inference request
# is refused (401) — fail closed, so a missing secret degrades to "no AI prose"
# (the backend falls back to templates) rather than an open GPU endpoint.
try:
    _secrets = [modal.Secret.from_name("onus-llm-auth")]
except Exception:
    _secrets = []


@app.function(
    image=llm_image,
    gpu="T4",
    secrets=_secrets,
    scaledown_window=300,   # scale to zero after 5 min idle -> $0 when unused
    timeout=600,
    max_containers=1,       # one 7B model instance is plenty for launch load
)
@modal.concurrent(max_inputs=4)
@modal.asgi_app()
def ollama_api():
    from fastapi import FastAPI, Request, Response, HTTPException
    import httpx

    # Boot Ollama once per container.
    subprocess.Popen(["ollama", "serve"])
    for _ in range(60):
        try:
            httpx.get("http://localhost:11434/api/tags", timeout=2)
            break
        except Exception:
            time.sleep(1)

    token = os.environ.get("OLLAMA_AUTH_TOKEN", "")
    if not token:
        print("ERROR: OLLAMA_AUTH_TOKEN unset - inference is REFUSED (401) until "
              "the onus-llm-auth secret is created and the app redeployed.")

    web = FastAPI()

    @web.get("/api/tags")
    async def tags():
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get("http://localhost:11434/api/tags")
        return Response(r.content, media_type="application/json")

    @web.post("/api/{path:path}")
    async def proxy(path: str, request: Request):
        # Fail closed: no configured token means the endpoint is misconfigured,
        # not open. Never serve inference without a matching bearer token.
        if not token or request.headers.get("authorization") != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="unauthorized")
        body = await request.body()
        # Generous timeout: ollama_client's own budget (240s+) is the real bound.
        async with httpx.AsyncClient(timeout=300) as c:
            r = await c.post(f"http://localhost:11434/api/{path}", content=body)
        return Response(r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type", "application/json"))

    return web
