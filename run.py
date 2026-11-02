import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("ASM_HOST", "0.0.0.0"),
        port=int(os.environ.get("ASM_PORT", "8000")),
        workers=1,
        log_level=os.environ.get("ASM_LOG_LEVEL", "info"),
    )
