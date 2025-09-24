"""Module for handling command events in a multi-server test environment."""

from typing import Union
from python_on_whales import Container, docker

ValidContainer = Union[Container, str]


def run_command(
    source: ValidContainer,
    command: str,
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
    docker.execute(source, ["bash", "-c", command], detach=detach)
