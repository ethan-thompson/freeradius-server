"""A state class to manage the state of the multi-server test environment."""

import asyncio
from collections.abc import Callable
import logging
from Validator import Validator  # pylint: disable=import-error


logger = logging.getLogger("__main__")

class State:
    """
    A class to represent the state of the multi-server test environment.
    """

    validator: Validator
    _timeout_handle: asyncio.TimerHandle

    def __init__(
        self,
        actions: list[callable] | None = None,
        rules_map: dict | None = None,
        timeout: int = 15,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        # actions is a list of callables that take no arguments and return None
        self.actions: list[Callable[[], None]] = actions if actions is not None else []

        self.timeout = timeout
        self._timeout_handle = None

        loop = loop or asyncio.get_event_loop()
        self.state_completed = loop.create_future()

        self.validator = Validator(
            rules_map if rules_map is not None else {}, self.state_completed
        )

        # When the state is marked as completed, cancel the timeout
        self.state_completed.add_done_callback(
            lambda _: self._timeout_handle.cancel() if self._timeout_handle else None
        )

        logger.debug(
            "State initialized with %d actions and timeout of %d seconds.",
            len(self.actions),
            self.timeout,
        )

    def enter_state(self) -> None:
        """
        Enter the state and execute all actions.
        """
        loop = asyncio.get_event_loop()

        # Set up the timeout to mark the state as completed after the specified duration
        def on_timeout() -> None:
            logger.info("State timed out after %d seconds", self.timeout)

            if not self.state_completed.done():
                logger.info("Marking state as completed due to timeout.")
                self.state_completed.set_result(True)

        self._timeout_handle = loop.call_later(self.timeout, on_timeout)

        for action in self.actions:
            logger.debug("Executing action: %s", action.__name__)
            action()

    async def wait_for_completion(self) -> None:
        """
        Wait for the state to be marked as completed.
        """
        await self.state_completed
