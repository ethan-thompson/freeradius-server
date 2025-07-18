"""multi_server_test.py
This script is used to run tests for a multi-server setup in a CI environment.
It uses Docker Compose to set up the environment and runs tests against it.
"""

import asyncio
import argparse
import logging
import signal
import sys
from pathlib import Path

from python_on_whales import DockerClient
from termcolor import colored

# Add a log handler for the INFO level
info_handler = logging.StreamHandler(sys.stdout)
info_handler.setLevel(logging.INFO)
info_handler.addFilter(lambda record: record.levelno == logging.INFO)
info_handler.setFormatter(logging.Formatter("%(message)s"))

not_info_handler = logging.StreamHandler(sys.stderr)
not_info_handler.setLevel(logging.DEBUG)
not_info_handler.addFilter(lambda record: record.levelno != logging.INFO)
not_info_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add the handlers to the logger
logger.addHandler(info_handler)


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
    logger.debug("Client connected.")
    try:
        data = await reader.readuntil(b"\n")
        message = data.decode().strip()
        logger.debug("Received message: %s", message)

        result = validation_func(message) if validation_func else True

        logger.info(
            "Message validation result: %s",
            colored(
                "PASSED" if result else "FAILED", "green" if result else "red"
            ),
        )

        if result:
            logger.info("Message validation passed.")
        else:
            logger.error("Message validation failed.")

    except Exception as e:
        logger.error("Error handling client: %s", e)
    finally:
        writer.close()
        await writer.wait_closed()
        logger.debug("Client disconnected.")


async def unix_server(
    socket_path: Path,
    validation_func: callable = None,
    ready_future: asyncio.Future = None,
) -> None:
    """
    Asynchronous server that listens on a Unix socket and processes incoming messages.

    Args:
        socket_path (Path): Path to the Unix socket.
        validation_func (callable, optional): Function to validate incoming messages.
        ready_future (asyncio.Future, optional): Future to signal when the server is ready.
    """
    logger.debug("Starting Unix server on %s", socket_path)
    if socket_path.exists():
        socket_path.unlink()

    try:
        server = await asyncio.start_unix_server(
            lambda r, w: handle_client(r, w, validation_func),
            path=str(socket_path),
        )

        # Make sure the socket is world writable
        socket_path.chmod(0o777)
    except PermissionError:
        logger.error("Permission denied for socket path: %s", socket_path)
        return

    logger.debug("Unix server started on %s", socket_path)

    # Signal that the server is ready
    if ready_future:
        ready_future.set_result(True)

    async with server:
        logger.debug("Unix server is running...")
        await server.serve_forever()


async def run_tests(
    compose_file: Path,
    ready_future: asyncio.Future,
    validated_result: asyncio.Future,
) -> None:
    """
    Runs tests in a multi-server setup using Docker Compose.

    Args:
        compose_file (Path): Path to the Docker Compose file.
        ready_future (asyncio.Future): Future to signal when the server is ready.
        validated_result (asyncio.Future): Future to signal when the validation is complete.
    """
    if not ready_future.done():
        logger.debug("Waiting for server to be ready...")
        await ready_future

    logger.info("Running tests with compose file: %s", compose_file)

    # Build the Docker Compose services
    client = DockerClient(compose_files=[compose_file])
    client.compose.build(quiet=True)

    # Start the Docker Compose services
    client.compose.up(detach=True)

    logger.info("Docker Compose services started.")

    # # Run the test command
    # command = (
    #     "echo 'testpass' | radtest testuser testpass freeradius 0 testing123 | socat - UNIX-CONNECT:%s"
    #     % output_socket
    # )

    # logger.info("Running command: %s", command)

    # # Execute the command in the Docker container
    # try:
    #     client.compose.execute(
    #         service="radius-client",
    #         command=["bash", "-c", command],
    #         tty=False,
    #         detach=True,
    #     )

    #     logger.info("Command executed successfully.")
    # except DockerException as e:
    #     logger.info("Command execution failed: %s", e)

    # Wait for the validation to complete
    logger.debug("Waiting for validation to complete...")
    await validated_result

    # Clean up the Docker Compose services
    client.compose.down()
    logger.info("Docker Compose services stopped.")


async def cleanup_and_shutdown() -> None:
    """
    Clean up the tasks by cancelling them all and waiting for them to finish.
    """
    logger.info("Shutting down the tests...")
    logger.debug("Cleaning up tasks and shutting down the event loop...")
    tasks = [
        task
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
    ]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.debug("Cleanup completed.")

    logger.debug("Stopping the event loop...")
    # Stop the event loop if it's running
    if asyncio.get_event_loop().is_running():
        asyncio.get_event_loop().stop()
    logger.debug("Event loop stopped.")


def main(compose_file: Path) -> None:
    """
    Main function to run the multi-server tests.

    Args:
        compose_file (Path): Path to the Docker Compose file.
    """
    # Run a test in an asynchronous event loop
    loop = asyncio.get_event_loop()

    try:
        # Set up the Unix server
        output_socket = Path("/var/run/multi-test/test.sock")
        ready_future = loop.create_future()
        validated_result = loop.create_future()

        def validation_func(message: str) -> bool:
            """
            Example validation function that checks if the message contains 'testpass'.
            """
            try:
                return "Access-Accept" in message
            finally:
                validated_result.set_result(True)

        loop.create_task(
            unix_server(output_socket, validation_func, ready_future)
        )

        # Add a signal handler to gracefully handle shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(cleanup_and_shutdown())
            )

        # Run the tests
        test_task = loop.create_task(
            run_tests(compose_file, ready_future, validated_result)
        )

        # Start the shutdown when the test completes
        test_task.add_done_callback(
            lambda _: asyncio.create_task(cleanup_and_shutdown())
        )

        # Run the event loop until all tasks are complete
        loop.run_forever()
    except Exception as e:
        logger.error("An error occurred while running tests: %s", e)
    finally:
        logger.debug("Removing output socket if it exists...")
        if output_socket.exists():
            output_socket.unlink()
        loop.close()

    logger.info("Multi-server tests completed.")


def parse_args(args=None, prog=__package__) -> argparse.Namespace:
    """
    Parses command line arguments for the main function.

    Args:
        args (list, optional): List of command line arguments. Defaults to None.
        prog (str, optional): Program name. Defaults to __package__.
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Run Docker client with specified compose file.",
    )
    parser.add_argument(
        "--compose_file",
        type=str,
        metavar="compose_file",
        help="Path to the Docker Compose file.",
        default=Path(Path(__file__).parent, "docker-compose.yml"),
    )
    parser.add_argument(
        "--debug",
        "-x",
        dest="debug",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args(args)


if __name__ == "__main__":
    parsed_args = parse_args()

    if parsed_args.debug:
        logging.getLogger(__name__).setLevel(logging.DEBUG)
        logger.addHandler(not_info_handler)
        print("Debug mode enabled.")

    main(compose_file=parsed_args.compose_file)
