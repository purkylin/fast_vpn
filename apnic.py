import asyncio
import hashlib
import functools
import os.path
import shutil
import aiohttp
import math

def cache_request():
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kw):
            url = kw['url']
            assert url, 'url can not be empty'

            key = md5(url)
            fname = f'.cache/{key}'
            if os.path.isfile(fname):
                with open(fname) as fp:
                    return fp.read()
            else:
                result = await func(*args, **kw)
                if not result:
                    return
                os.makedirs(os.path.dirname(fname), exist_ok=True)
                with open(fname, 'w') as fp:
                    fp.write(result)
                return result
        return wrapper
    return decorator


@cache_request()
async def fetch_page(url, cookies=None, headers=None, params=None):
    agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15'
    combined_headers = {
        'User-Agent': agent,
    }

    if headers:
        combined_headers.update(headers)

    async with aiohttp.ClientSession(cookies=cookies) as session:
        async with session.get(url, headers=combined_headers, params=params) as response:
            return await response.text()


def md5(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode()).hexdigest()


def parse(content, country='CN'):
    # registry|cc|type|start|value|date|status[|extensions...]

    lines = content.split('\n')
    out: list[str] = []

    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith('#'):
            continue

        arr = raw.split('|')
        if len(arr) != 7:
            continue

        if arr[1] == country and arr[6] == 'allocated' and arr[2] == 'ipv4':
            ip = arr[3]
            count = int(arr[4])
            mask = 32 - int(math.log(count, 2))
            result = f'{ip}/{mask}'
            out.append(result)
            print(result)
        

    if len(out) > 0:
        with open(f'{country}.txt', 'w') as fp:
            for item in out:
                print(item, file=fp)


async def main():
    url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    result = await fetch_page(url=url, country='CN')
    parse(result)

def clear_cache():
    shutil.rmtree('.cache')

# clear_cache()
asyncio.run(main())