import asyncio
import logging
import signal
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


SOCKET_PATH = Path("/var/run/multi-test/test.sock")

async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    validation_func: callable = None,
) -> None:
    """
    Handles incoming client connections and processes messages.

    Args:
        reader (asyncio.StreamReader): Reader for the incoming data.
        writer (asyncio.StreamWriter): Writer for sending responses.
        validation_func (callable, optional): Function to validate incoming messages.
    """
    logger.info("Client connected.")
    # addr = writer.get_extra_info("peername")
    # logger.info("Connection from %s", addr)

    try:
        data = await reader.readuntil(b"\n")
        message = data.decode().strip()
        logger.info("Received message: %s", message)

        result = validation_func(message) if validation_func else True
        if result:
            logger.info("Message validation passed.")
        else:
            logger.error("Message validation failed.")

        # Process the message and send a response
        # response = f"Processed: {message}"
        # writer.write(response.encode())
        # await writer.drain()
        # logger.info("Sent response: %s", response)
    except Exception as e:
        logger.error("Error handling client: %s", e)
    finally:
        writer.close()
        await writer.wait_closed()
        logger.info("Client disconnected.")


async def unix_server(
    loop: asyncio.AbstractEventLoop,
    socket_path: Path,
    validation_func: callable = None,
    ready_future: asyncio.Future = None,
) -> None:
    """
    Asynchronous server that listens on a Unix socket and processes incoming messages.

    Args:
        loop (asyncio.AbstractEventLoop): The event loop to run the server.
        socket_path (Path): Path to the Unix socket.
        validation_func (callable, optional): Function to validate incoming messages.
    """
    logger.info("Starting Unix server on %s", socket_path)
    if socket_path.exists():
        socket_path.unlink()

    # server = await asyncio.start_unix_server(
    #     lambda r, w: handle_client(r, w, validation_func),
    #     path=str(socket_path),
    #     loop=loop,
    # )

    try:
        # server = await loop.create_unix_server(
        #     lambda r, w: handle_client(r, w, validation_func),
        #     path=str(socket_path),
        # )
        server = await asyncio.start_unix_server(
            lambda r, w: handle_client(r, w, validation_func),
            path=str(socket_path),
        )

        # Make sure the socket is world writable
        socket_path.chmod(0o777)
    except PermissionError:
        logger.error("Permission denied for socket path: %s", socket_path)
        return

    logger.info("Unix server started on %s", socket_path)

    if ready_future:
        ready_future.set_result(True)

    async with server:
        logger.info("Unix server is running...")
        await server.serve_forever()


def main():
    loop = asyncio.get_event_loop()
    socket_path = Path(SOCKET_PATH)
    ready_future = loop.create_future()

    try:
        server_task = loop.create_task(
            unix_server(loop, socket_path, lambda msg: 'Access-Accept' in msg, ready_future=ready_future)
        )

        # Set up signal handling for graceful shutdown
        def shutdown():
            logger.info("Shutting down server...")
            server_task.cancel()
            loop.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown)

        loop.run_forever()
    except Exception as e:
        logger.error("An error occurred: %s", e)
    finally:
        if socket_path.exists():
            socket_path.unlink()
        loop.close()
        logger.info("Server stopped.")


if __name__ == "__main__":
    main()
