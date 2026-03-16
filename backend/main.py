import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import attacks, analytics, bots, flagged, stats

app = FastAPI(title="PhishNet API", version="0.1.0")

allowed_origins = [
    "http://localhost:5173",
]
if os.environ.get("FRONTEND_URL"):
    allowed_origins.append(os.environ["FRONTEND_URL"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(attacks.router, prefix="/api")
app.include_router(bots.router, prefix="/api")
app.include_router(flagged.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(analytics.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
