"""Module for handling command events in a multi-server test environment."""

import logging
import re

from typing import Union
from python_on_whales import Container, docker

ValidContainer = Union[Container, str]


def run_command(
    source: ValidContainer,
    command: str,
    logger: logging.Logger,
    test_name: str,
    detach: bool = False,
) -> None:
    """
    Execute a command in a specified container.

    Args:
        container (ValidContainer): The container to execute the command in.
        command (str): The command to execute.
        detach (bool, optional): Whether to run the command in detached mode. Defaults to False.

    Raises:
        python_on_whales.exceptions.NoSuchContainer: If the container does not exist.
    """

    # Using regex, search the command for any ${container_name} patterns and replace them
    # with the actual container name using the docker compose project name as a prefix.
    pattern = re.compile(r"\$\{([a-zA-Z0-9_-]+)\}")
    matches = pattern.findall(command)
    for match in matches:
        full_container_name = f"{test_name}-{match}-1"
        command = command.replace(f"${{{match}}}", full_container_name)

    logger.debug("Running command in %s: %s", source, command)
    docker.execute(source, ["bash", "-c", command], detach=detach)

def get_events() -> dict[str, callable]:
    """
    Returns a dictionary of available events that can be performed on containers.

    Returns:
        dict[str, callable]: A dictionary mapping event names to their corresponding functions.
    """
    return {
        "run_command": run_command,
        "execute_command": run_command,
        "command": run_command,
    }
