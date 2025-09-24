"""Network Events for Multi-Server CI tests."""

from typing import Union
import asyncio
from functools import singledispatch

from python_on_whales import Network, Container, docker

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
async def _(network: ValidNetwork, targets: list[ValidContainer], timeout: int) -> None:
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
def packet_loss(source: ValidContainer, interface: str, loss: float) -> None:
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
            "tc",
            "qdisc",
            "add",
            "dev",
            interface,
            "root",
            "netem",
            "loss",
            f"{loss}%",
        ],
        detach=True,
    )

    logger.debug(f"Applied {loss}% packet loss on {source} ({interface})")
