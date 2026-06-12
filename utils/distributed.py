"""
utils/distributed.py — Distributed scanning con Redis queue.

Permite dividir un target grande (muchos subdominios o un wordlist enorme)
en N workers que consumen una cola Redis.

Modelo:
  - El master encola tareas: `{type, target, params}`.
  - Cada worker hace `BLPOP` de la cola y procesa.
  - Resultados se publican en otra lista `scan:results:{scan_id}`.

CLI suggested usage:
  python -m utils.distributed master --targets targets.txt --redis redis://localhost:6379
  python -m utils.distributed worker --redis redis://localhost:6379 --queue scan:queue

Requiere: pip install redis aioredis
Sin redis instalado, el módulo expone stubs que lanzan ImportError diferida.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from typing import Optional


def _require_redis():
    try:
        import redis.asyncio as aioredis  # type: ignore
        return aioredis
    except ImportError as e:
        raise ImportError(
            "Modo distribuido requiere 'redis'. Instala con: pip install redis"
        ) from e


class DistributedMaster:
    """Encola targets en Redis."""

    def __init__(self, redis_url: str = "redis://localhost:6379", queue: str = "vul:queue"):
        self.redis_url = redis_url
        self.queue     = queue
        self.scan_id   = uuid.uuid4().hex[:12]
        self.r = None

    async def connect(self):
        aioredis = _require_redis()
        self.r = aioredis.from_url(self.redis_url, decode_responses=True)
        await self.r.ping()

    async def enqueue_targets(self, targets: list[str], scan_opts: dict):
        for t in targets:
            task = {
                "scan_id": self.scan_id,
                "target":  t,
                "opts":    scan_opts,
            }
            await self.r.rpush(self.queue, json.dumps(task))

    async def collect_results(self, n: int, timeout: int = 600) -> list[dict]:
        """Espera n resultados de los workers."""
        results = []
        results_key = f"vul:results:{self.scan_id}"
        for _ in range(n):
            r = await self.r.blpop(results_key, timeout=timeout)
            if r is None:
                break
            _, raw = r
            try:
                results.append(json.loads(raw))
            except Exception:
                continue
        return results


class DistributedWorker:
    """Consume tareas y publica resultados."""

    def __init__(self, redis_url: str = "redis://localhost:6379", queue: str = "vul:queue"):
        self.redis_url = redis_url
        self.queue     = queue
        self.r = None

    async def connect(self):
        aioredis = _require_redis()
        self.r = aioredis.from_url(self.redis_url, decode_responses=True)
        await self.r.ping()

    async def run_forever(self):
        from scanner import scan
        from utils.vuln import Vuln  # noqa
        print(f"[worker] consuming {self.queue}")
        while True:
            task = await self.r.blpop(self.queue, timeout=0)
            if not task:
                continue
            _, raw = task
            try:
                t = json.loads(raw)
            except Exception:
                continue

            target = t["target"]
            opts   = t.get("opts", {})
            scan_id = t["scan_id"]
            print(f"[worker] scanning {target}")
            try:
                vulns, meta, duration = await scan(target, **opts)
                result = {
                    "target":   target,
                    "duration": duration,
                    "vulns":    [v.__dict__ for v in vulns],
                    "meta":     meta,
                }
            except Exception as e:
                result = {"target": target, "error": str(e)}

            await self.r.rpush(f"vul:results:{scan_id}", json.dumps(result, default=str))


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["master", "worker"])
    p.add_argument("--redis", default="redis://localhost:6379")
    p.add_argument("--queue", default="vul:queue")
    p.add_argument("--targets", help="Archivo con lista de URLs (modo master)")
    p.add_argument("--full", action="store_true")
    p.add_argument("--active", action="store_true")
    args = p.parse_args()

    async def _run():
        if args.mode == "master":
            if not args.targets:
                print("--targets required en modo master"); return
            with open(args.targets, "r") as f:
                lst = [line.strip() for line in f if line.strip()]
            m = DistributedMaster(args.redis, args.queue)
            await m.connect()
            opts = {"full_scan": args.full, "active_scan": args.active}
            await m.enqueue_targets(lst, opts)
            print(f"[master] enqueued {len(lst)} targets, scan_id={m.scan_id}")
            results = await m.collect_results(len(lst))
            with open(f"distributed_{m.scan_id}.json", "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[master] saved → distributed_{m.scan_id}.json")
        else:
            w = DistributedWorker(args.redis, args.queue)
            await w.connect()
            await w.run_forever()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
