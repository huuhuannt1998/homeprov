"""Host-side tunnel: listen on 127.0.0.1:LPORT and forward each connection through `docker exec -i CONTAINER python3
relay.py TARGET TPORT`, so the host's harness and browser reach the Domoticz web server on the internal network dz-net
from the harness container's address. Usage: tunnel.py LPORT CONTAINER TARGET TPORT"""
import asyncio
import sys

LPORT, CONTAINER, TARGET, TPORT = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]


async def pump(reader, writer):
    try:
        while True:
            b = await reader.read(65536)
            if not b:
                break
            writer.write(b)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            if hasattr(writer, "write_eof") and writer.can_write_eof():
                writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def handle(creader, cwriter):
    p = await asyncio.create_subprocess_exec(
        "docker", "exec", "-i", CONTAINER, "python3", "-u", "/dzsrc/harness/relay.py", TARGET, TPORT,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    t1 = asyncio.create_task(pump(creader, p.stdin))
    t2 = asyncio.create_task(pump(p.stdout, cwriter))
    await t2                      # the connection ends when the hub side ends
    t1.cancel()
    try:
        cwriter.close()
    except OSError:
        pass
    try:
        p.kill()
    except ProcessLookupError:
        pass


async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", LPORT)
    async with srv:
        await srv.serve_forever()


asyncio.run(main())
