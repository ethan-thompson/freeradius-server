"""Network Events for Multi-Server CI tests."""

from typing import Union
import asyncio
from functools import singledispatch
import logging

from python_on_whales import Network, Container, docker
from python_on_whales.exceptions import DockerException

ValidNetwork = Union[Network, str]
ValidContainer = Union[Container, str]


@singledispatch
def disconnect(network: ValidNetwork, targets: list[ValidContainer]) -> None:
    """
    Simulate network disconnection.

    Args:
        network (ValidNetwork): The network to disconnect from.
        targets (list[ValidContainer]): List of valid containers to disconnect.
    """
    for target in targets:
        docker.network.disconnect(network, target)


@disconnect.register
def _(network: ValidNetwork, source: ValidContainer) -> None:
    """
    Simulate network disconnection.

    Args:
        network (ValidNetwork): The network to disconnect from.
        source (ValidContainer): The valid container to disconnect.
    """
    docker.network.disconnect(network, source)


@disconnect.register
async def _(
    network: ValidNetwork, targets: list[ValidContainer], timeout: int
) -> None:
    """
    Simulate network disconnection with a timeout.

    Args:
        network (ValidNetwork): The network to disconnect from.
        targets (list[ValidContainer]): List of valid containers to disconnect.
        timeout (int): Time in seconds to wait before reconnecting.
    """
    for target in targets:
        docker.network.disconnect(network, target)

    await asyncio.sleep(timeout)
    reconnect(network, targets)


@disconnect.register
async def _(
    network: ValidNetwork, source: ValidContainer, timeout: int
) -> None:
    """
    Simulate network disconnection with a timeout.

    Args:
        network (ValidNetwork): The network to disconnect from.
        source (ValidContainer): The valid container to disconnect.
        timeout (int): Time in seconds to wait before reconnecting.
    """
    await disconnect(network, source, timeout=timeout)


def reconnect(network: ValidNetwork, targets: list[ValidContainer]) -> None:
    """
    Simulate network reconnection.

    Args:
        network (ValidNetwork): The network to reconnect to.
        targets (list[ValidContainer]): List of valid containers to reconnect.
    """
    for target in targets:
        docker.network.connect(network, target)


# TODO: the interface that tc operates on may be different for different containers
#       we may need to pass that in as an argument or determine it dynamically
def packet_loss(
    source: ValidContainer, interface: str, loss: float, logger: logging.Logger
) -> None:
    """
    Simulate packet loss on specified containers.

    Args:
        targets (list[ValidContainer]): List of valid containers to apply packet loss.
        interface (str): The network interface to apply packet loss on.
        loss (float): Percentage of packet loss to simulate.
    """
    docker.execute(
        source,
        [
            "bash",
            "-c",
            f"tc qdisc replace dev {interface} root netem loss {loss}%",
        ],
        detach=True,
    )

    try:
        result = docker.execute(
            source,
            ["bash", "-c", "ping -c 10 -W 2 8.8.8.8 || true"],
            detach=False,
        )
    except DockerException as e:
        # Extract the stdout content from the exception
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        exit_code = e.return_code or None

        # Check if it's the expected 100% loss case
        if f"{loss}% packet loss" in stdout:
            result = stdout
        else:
            logger.error(
                f"Unexpected ping failure (code {exit_code}): {stdout}\n{stderr}"
            )
            return
    else:
        # Success case: capture output
        stdout = result
        result = stdout

    # Now continue processing result
    if "100% packet loss" in result or f"{loss}% packet loss" in result:
        logger.debug(
            f"Packet loss of {loss}% verified on {source} ({interface})"
        )
    else:
        logger.error(
            f"Unexpected packet loss result on {source} ({interface})"
        )
        logger.debug(f"Ping output:\n{result}")

    logger.debug(f"Applied {loss}% packet loss on {source} ({interface})")


def get_events() -> dict[str, callable]:
    """
    Returns a dictionary of available network events that can be performed on containers.

    Returns:
        dict[str, callable]: A dictionary mapping event names to their corresponding functions.
    """
    return {
        "disconnect": disconnect,
        "network_disconnect": disconnect,
        "reconnect": reconnect,
        "network_reconnect": reconnect,
        "packet_loss": packet_loss,
    }
