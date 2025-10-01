"""A listener to handle incoming messages from containers."""

import asyncio
import logging
from pathlib import Path


class Listener:
    """
    A class to represent a listener that handles incoming messages from containers.
    """

    def __init__(
        self,
        socket_path: Path,
        msg_queue: asyncio.Queue,
        ready_future: asyncio.Future,
        logger: logging.Logger = logging.getLogger("__main__"),
    ) -> None:
        self.messages = []
        self.socket_path = socket_path
        self.msg_queue = msg_queue
        self.ready_future = ready_future
        self.logger = logger

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handles incoming client connections and processes messages.

        Args:
            reader (asyncio.StreamReader): Reader for the incoming data.
            writer (asyncio.StreamWriter): Writer for sending responses.
            msg_queue (asyncio.Queue, optional): Queue to put received messages into.
        """
        self.logger.debug("Client connected.")
        try:
            while True:
                data = await reader.readuntil(b"\n")
                message = data.decode().strip()
                self.logger.debug("Received message: %s", message)

                trigger_name, trigger_value = message.split(" ", 1)

                self.msg_queue.put_nowait((trigger_name, trigger_value))
        except asyncio.IncompleteReadError:
            self.logger.debug("Client disconnected.")
        finally:
            writer.close()
            await writer.wait_closed()
            self.logger.debug("Client disconnected.")

    async def start(self) -> None:
        """
        Starts the listener server.
        """
        self.logger.debug("Starting listener on %s", self.socket_path)

        if self.socket_path.exists():
            # The path may be a directory if compose tried to mount it as a volume before
            # we created it
            if self.socket_path.is_dir():
                self.socket_path.rmdir()
            else:
                self.socket_path.unlink()

        try:
            server = await asyncio.start_unix_server(
                self.handle_connection,
                path=self.socket_path,
            )

            # Make sure the socket is world writable
            self.socket_path.chmod(0o777)
        except PermissionError as e:
            self.logger.error("Permission error starting listener: %s", e)
            return

        self.logger.debug("Listener started, setting ready future.")

        # Notify that the server is ready
        if not self.ready_future.done():
            self.ready_future.set_result(True)

        async with server:
            self.logger.debug("Listener running.")
            await server.serve_forever()
