"""A Test object to manage the multi-server tests."""

import asyncio
from functools import partial
import logging
from pathlib import Path
import re

from python_on_whales import DockerClient

from state import State  # pylint: disable=import-error
from listener import Listener  # pylint: disable=import-error


def create_test_logger(name: str) -> logging.Logger:
    """
    Create a logger for the test with the specified name.

    Args:
        name (str): The name of the test.

    Returns:
        logging.Logger: Configured logger for the test.
    """
    logger = logging.getLogger("Test." + name)
    logger.setLevel(logging.getLogger("__main__").level)

    # Copy any handlers from the main logger to this one
    for h in logging.getLogger("__main__").handlers:
        logger.addHandler(h)

    return logger


class Test:
    """
    A class to represent a multi-server test.
    """

    def __init__(
        self,
        name: str,
        states: list[State],
        compose_file: Path,
        timeout: float,
        detail_level: int,
        loop: asyncio.AbstractEventLoop,
        logger: logging.Logger = None,
    ) -> None:
        self.name = name
        self.states = states
        self.compose_file = compose_file
        self.timeout = timeout
        self.loop = loop
        self.logger = logger or create_test_logger(name)
        self.detail_level = detail_level
        self.queue: asyncio.Queue = asyncio.Queue()
        self.listener_task: asyncio.Task = None
        self.client = DockerClient(
            compose_files=[self.compose_file], compose_project_name=self.name
        )
        self.output_socket = Path("/var/run/multi-test", self.name + ".sock")
        self.logging_task: asyncio.Task = None
        self.validation_task: asyncio.Task = None

    async def __setup_test(self, log_containers: bool) -> None:
        """
        Sets up the test by initializing necessary resources.

        Args:
            log_containers (bool): Whether to log container outputs.
        """
        self.logger.info("Setting up test: %s", self.name)

        ready_future = self.loop.create_future()

        self.listener_task = self.loop.create_task(
            Listener(
                self.output_socket, self.queue, ready_future, self.logger
            ).start()
        )

        # Wait for the listener to be ready
        await ready_future

        self.logger.info(
            "Listener is ready. Beginning test setup for %s.", self.name
        )

        # Build the Docker Compose services
        self.client.compose.build(quiet=True)

        # Start the Docker Compose services
        if log_containers:
            compose_up = partial(
                self.client.compose.up,
                stream_logs=True,
            )

            logs = await self.loop.run_in_executor(None, compose_up)

            async def stream_logs() -> None:
                try:
                    while True:
                        log = await self.loop.run_in_executor(
                            None, next, logs, None
                        )
                        if log is None:
                            pass
                        else:
                            log_line = log[1].decode().strip()
                            self.logger.debug(
                                "[compose] %s: %s", log[0], log_line
                            )
                except Exception as e:
                    self.logger.error(
                        "Error while streaming compose logs: %s", e
                    )

            self.logging_task = self.loop.create_task(stream_logs())

        else:
            compose_up = partial(
                self.client.compose.up,
                detach=True,
                quiet=True,
            )
            self.loop.run_in_executor(None, compose_up)

        # Wait a moment to ensure everything is stable
        # TODO: Think about a better way to do this without a hardcoded sleep
        #  -- perhaps a healthcheck?
        await asyncio.sleep(2)

        # List the containers
        containers = self.client.compose.ps()
        for container in containers:
            self.logger.debug("Container %s is running.", container.name)

    async def __teardown_test(self) -> None:
        """
        Cleans up resources used by the test, such as the listener task and socket file.
        """
        self.logger.info("Cleaning up test: %s", self.name)

        if self.logging_task:
            self.logging_task.cancel()
            try:
                await self.logging_task
            except asyncio.CancelledError:
                pass

        if self.validation_task:
            self.validation_task.cancel()
            try:
                await self.validation_task
            except asyncio.CancelledError:
                pass

        # Tear down the containers
        compose_down = partial(
            self.client.compose.down,
            quiet=True,
        )
        await self.loop.run_in_executor(None, compose_down)

        # Ensure all containers are stopped
        containers = self.client.compose.ps()
        if containers:
            for container in containers:
                self.logger.warning(
                    "Container %s is still running during teardown.",
                    container.name,
                )
        else:
            self.logger.debug("All containers have been stopped.")

        if self.listener_task:
            self.listener_task.cancel()
            try:
                await self.listener_task
            except asyncio.CancelledError:
                pass

        # Remove the socket file
        if self.output_socket.exists():
            self.output_socket.unlink()

        self.logger.info("Cleanup complete for test: %s", self.name)

    async def run(self, log_containers: bool) -> None:
        """
        Runs the test by orchestrating the execution of states and managing resources.

        Args:
            log_containers (bool): Whether to log container outputs.
        """
        try:
            await self.__setup_test(log_containers)

            test_task = self.loop.create_task(self.__run())
            await asyncio.wait_for(test_task, timeout=self.timeout)
        except asyncio.TimeoutError:
            self.logger.error(
                "Test %s timed out after %.2f seconds", self.name, self.timeout
            )
        finally:
            await self.__teardown_test()

    async def __run(self) -> None:
        """
        Internal method to run the test states sequentially.
        """
        self.logger.info("Starting test: %s", self.name)

        self.logger.info("Starting test states for %s.", self.name)
        test_results = []
        for state in self.states:
            self.logger.debug(
                "Processing state: %s - %s", state.name, state.description
            )

            # Register new validator for the current state
            # Clear the message queue to avoid processing old messages
            self.logger.debug("Clearing message queue for new state.")
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

            # Next, setup the state's validator
            self.logger.debug("Setting up validator for state: %s", state.name)
            if self.validation_task:
                # Swap out the previous validation task
                self.validation_task.cancel()
                try:
                    await self.validation_task
                except asyncio.CancelledError:
                    pass
            self.validation_task = self.loop.create_task(
                state.validator.start_validating(self.queue)
            )

            # Now, enter the state
            self.logger.debug("Entering state: %s", state.name)
            await state.enter_state()

            # Wait for the state to complete
            self.logger.debug("Waiting for state completion: %s", state.name)
            await state.wait_for_completion()

            self.logger.info("State completed: %s", state.name)
            test_results.append(
                state.validator.get_results_str(self.detail_level)
            )
            self.logger.info(
                " %s %s",
                f"Test.{self.name}",
                state.validator.get_results_str(self.detail_level),
            )
        self.logger.info("Test completed: %s", self.name)

        # Remove the coloring from the test results before logging to file
        def strip_ansi(text):
            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
            return ansi_escape.sub('', text)

        test_results = [strip_ansi(r) for r in test_results]

        file_logger = logging.getLogger("file")
        for result in test_results:
            file_logger.info("%s %s", f"Test.{self.name}", result)
