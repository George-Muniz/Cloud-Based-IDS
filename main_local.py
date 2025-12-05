#Local development entrypoint.
#Simply imports and exposes the FastAPI app to run it locally (e.g., with uvicorn).
import uvicorn
from api.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8081, reload=True)
