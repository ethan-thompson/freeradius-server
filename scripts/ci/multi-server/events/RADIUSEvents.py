"""Module for RADIUS-related events in a multi-server CI environment."""

from typing import Union
from python_on_whales import Container, docker

import logging
logger = logging.getLogger("__main__")

ValidContainer = Union[Container, str]

def access_request(
    source: ValidContainer,
    target: ValidContainer,
    secret: str,
    username: str,
    password: str,
) -> None:
    """
    Simulate a RADIUS access request.

    Args:
        container (ValidContainer): The container to execute the command in.
        command (str): The command to execute.

    Raises:
        python_on_whales.exceptions.NoSuchContainer: If the container does not exist.
    """
    logger.debug(
        "Sending RADIUS access request from %s to %s for user %s",
        source,
        target,
        username,
    )
    command = f"echo {password} | radtest {username} {password} {target} 0 {secret} || true"

    docker.execute(source, ["bash", "-c", command], detach=True)
