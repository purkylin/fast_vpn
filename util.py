import functools
import asyncio
import subprocess

def sync_to_async(func):
    @functools.wraps(func)
    def wrapper(*args, **kw):
        return asyncio.to_thread(lambda: func(*args, **kw))
    return wrapper

def run(cmd: str):
    subprocess.run(cmd, shell=True, check=True)