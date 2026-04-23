import asyncio
from .protocol import build_dns_query, parse_dns_response, QTYPE
from .cache import AsyncLRUCache
from .limiter import TokenBucket
from .resolver import AsyncMultiResolver, ResolverEndpoint
from .dnssec import validate_dnssec_chain


class DNSClient:
    def __init__(self, resolvers: list[str], cache_size: int = 4096, rate: float = 10.0, dnssec: bool = False):
        endpoints = [ResolverEndpoint(host=h) for h in resolvers]
        self.resolver = AsyncMultiResolver(endpoints)
        self.cache = AsyncLRUCache(maxsize=cache_size)
        self.limiter = TokenBucket(rate=rate)
        self.dnssec = dnssec
    
    async def resolve(self, domain: str, qtype: int = QTYPE.A) -> list[dict]:
        key = f"{domain}:{qtype}"
        cached = await self.cache.get(key)
        if cached:
            return cached
        
        await self.limiter.acquire()
        query, tx_id = build_dns_query(domain, qtype)
        resp = await self.resolver.resolve(query, tx_id)
        result = parse_dns_response(resp, tx_id)

        if self.dnssec:
            # await validate_dnssec_chain(self.resolver, domain, result["answers"])
            pass # Hook for DNSSEC validation

        if result["answers"]:
            await self.cache.put(key, result["answers"], result["answers"][0]["ttl"])
        return result["answers"]
    
    async def close(self):
        await self.resolver.close()