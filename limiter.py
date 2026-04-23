import time
import asyncio

class TokenBucket:
    def __init__(self, rate: float = 10.0, capacity: float = 20.0):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_time = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.time()
            self.tokens = min(self.capacity, self.tokens + (now - self.last_time) * self.rate)
            self.last_time = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
        # Wait outside lock to avoid blocking others
        await asyncio.sleep(0.1)
        await self.acquire()