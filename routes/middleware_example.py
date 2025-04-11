import time

from fastapi import FastAPI, Request, APIRouter
from fastapi.staticfiles import StaticFiles

middleware_test = APIRouter()
middleware_test.mount("/static", StaticFiles(directory="static"), name="static")


# @middleware_test.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response
