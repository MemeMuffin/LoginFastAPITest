from fastapi import FastAPI
from routes.user_login import login
from routes.middleware_example import middleware_test


app = FastAPI()
app.include_router(login)
# app.include_router(middleware_test)
