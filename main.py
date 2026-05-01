import asyncio
from client import DNSClient
from protocol import QTYPE

async def main():
    client = DNSClient(
        resolvers=["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"],
        cache_size=2048,
        rate=15.0,
        dnssec=False
    )

    domains = ["google.com", "cloudflare.com", "github.com", "example.com"]
    tasks = [client.resolve(domain, QTYPE.AAAA) for domain in domains]

    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                print(f"{domain}: {result}")
            else:
                ips = [r["value"] for r in result if r["type"] in ("A", "AAAA")]
                print(f"{domain} -> {', '.join(ips) if ips else 'No records'}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())