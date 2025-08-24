from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/__debug_webhook")
async def __debug_webhook(request: Request):
    await request.body()      # read but ignore
    return {"ok": True}