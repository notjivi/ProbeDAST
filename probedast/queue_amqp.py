"""RabbitMQ-backed job queue (design doc Phase 4, Days 20-21): durable jobs
with manual acks, so a crashed worker's job is requeued instead of lost, and
a crashed scan can resume from where it left off.

**Not yet wired into Orchestrator** — `orchestrator.py` currently always
uses the in-process `JobQueue` (asyncio.Queue). This module implements the
same job shape (`probedast.models.Job`) against aio-pika so that swapping it
in is a matter of changing what `Orchestrator._scan_endpoints` constructs,
not a redesign:

    queue = AMQPJobQueue(amqp_url)   # instead of JobQueue()
    await queue.connect()
    ...
    await queue.publish(job)
    ...
    async for job in queue.consume():
        ...                          # process, then:
        await queue.ack(job)

Low prefetch (`prefetch_count`) matters: it's what stops one slow worker
hoarding jobs and starving the others (Section 5.4).
"""
from __future__ import annotations
import json
from dataclasses import asdict

from .models import Job

MAIN_QUEUE = "probedast.jobs"
TIME_QUEUE_PREFIX = "probedast.jobs.time."  # one per host, serial consumption


class AMQPJobQueue:
    def __init__(self, amqp_url: str, prefetch_count: int = 4):
        self.amqp_url = amqp_url
        self.prefetch_count = prefetch_count
        self._connection = None
        self._channel = None

    async def connect(self):
        import aio_pika
        self._connection = await aio_pika.connect_robust(self.amqp_url)
        self._channel = await self._connection.channel()
        await self._channel.set_qos(prefetch_count=self.prefetch_count)
        await self._channel.declare_queue(MAIN_QUEUE, durable=True)

    async def close(self):
        if self._connection:
            await self._connection.close()

    def _queue_name(self, job: Job, host: str | None = None) -> str:
        if job.detector == "sqli_time" and host:
            return f"{TIME_QUEUE_PREFIX}{host}"
        return MAIN_QUEUE

    async def publish(self, job: Job, host: str | None = None):
        import aio_pika
        qname = self._queue_name(job, host)
        if qname != MAIN_QUEUE:
            await self._channel.declare_queue(qname, durable=True)
        body = json.dumps(job.to_dict()).encode()
        await self._channel.default_exchange.publish(
            aio_pika.Message(body=body, delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
            routing_key=qname,
        )

    async def consume(self, queue_name: str = MAIN_QUEUE):
        """Yields (job, message) pairs. Caller must ack() or nack() the message --
        detectors are idempotent (design doc Section 8), so a requeue on crash is safe."""
        queue = await self._channel.declare_queue(queue_name, durable=True)
        async with queue.iterator() as it:
            async for message in it:
                job = Job(**json.loads(message.body))
                yield job, message

    async def ack(self, message):
        await message.ack()

    async def nack(self, message, requeue: bool = True):
        await message.nack(requeue=requeue)
