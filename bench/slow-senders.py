#!/usr/bin/env python3
"""Opens token requests whose bodies arrive a trickle at a time, and holds them open.

The attack a stress run checks for: a stranger opening as many requests as the instance has
turns and sending each body just fast enough that the server's own minimum data rate does not
drop the connection. If the instance took a turn before reading a body, these would hold every
turn it has and nobody else would be served. Standard library only, like everything else the
rig runs on the host.

    ./slow-senders.py --connections 300 --seconds 60

Reports how many requests were opened, and how many the server was still holding open at the
end, so a run can tell "the server hung up on them" from "they were held and did no harm".
"""

import argparse
import asyncio
import time


async def trickle(host, port, rate, seconds, length, held):
    writer = None
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(
            (
                "POST /oauth2/token HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {length}\r\n"
                "\r\n"
            ).encode("ascii")
        )
        await writer.drain()
        ends = time.monotonic() + seconds
        sent = 0
        while time.monotonic() < ends and sent < length:
            writer.write(b"a" * rate)
            await writer.drain()
            sent += rate
            if reader.at_eof():
                return
            await asyncio.sleep(1)
        held.append(1)
    except (ConnectionError, OSError):
        return
    finally:
        if writer is not None:
            writer.close()


async def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5100)
    parser.add_argument("--connections", type=int, default=300)
    parser.add_argument("--seconds", type=float, default=60)
    # Just above Kestrel's default minimum body data rate of 240 bytes a second.
    parser.add_argument("--rate", type=int, default=300, help="bytes a second per request")
    parser.add_argument("--length", type=int, default=1_000_000, help="the Content-Length each claims")
    arguments = parser.parse_args()

    held = []
    await asyncio.gather(
        *(
            trickle(arguments.host, arguments.port, arguments.rate, arguments.seconds, arguments.length, held)
            for _ in range(arguments.connections)
        )
    )
    print(f"slow senders: {arguments.connections} opened, {len(held)} still held open after {arguments.seconds:.0f}s")


if __name__ == "__main__":
    asyncio.run(main())
