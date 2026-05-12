"""Background workers that run inside the FastAPI process.

Workers are long-running background threads launched from the app's ASGI
lifespan handler. They share nothing with HTTP request threads beyond
explicitly injected service singletons, so they can be unit-tested in
isolation and swapped out for test doubles without spinning up the full
app.
"""
