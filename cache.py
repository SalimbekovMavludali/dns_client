import time
import asyncio
from collections import OrderedDict
from typing import Optional

class AsyncLRUCache:
    def __init__(self, maxsize: int = 4096, max_ttl: int = 3600, min_ttl: int = 30):
        self._cache = OrderedDict()
        self._maxsize = maxsize
        self._max_ttl = max_ttl
        self._min_ttl = min_ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[list[dict]]:
        async with self._lock:
            if key in self._cache:
                answers, expiry = self._cache[key]
                if time.time() < expiry:
                    self._cache.move_to_end(key)
                    return answers
                del self._cache[key]
            return None

    async def put(self, key: str, answers: list[dict], ttl: int):
        async with self._lock:
            capped_ttl = max(self._min_ttl, min(ttl, self._max_ttl))
            self._cache[key] = (answers, time.time() + capped_ttl)
            self._cache.move_to_end(key)
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)