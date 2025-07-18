"""test_runner.py
Test runner for multi-server setup using Docker Compose.
This script sets up a multi-server environment, runs tests, and tears down the environment.
"""

import asyncio
import logging
import socket
import os
from pathlib import Path
import unittest

from python_on_whales import DockerClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COMPOSE_FILE = Path(Path(__file__).parent, "docker-compose.yml")

async def validate_on_response(loop: asyncio.AbstractEventLoop, socket: socket.socket, validation_func: callable) -> bool:
    """
    Validates the response from a socket connection using a validation function.

    Args:
        loop (asyncio.AbstractEventLoop): The event loop to run the validation.
        socket (socket.socket): The socket to read from.
        validation_func (callable): A function that takes a string and returns True if valid.

    Returns:
        bool: True if the response is valid, False otherwise.
    """

    # Wait for the response


    # validate the response
    return validation_func(response)

class MultiServerTest(unittest.TestCase):
    """Test case for multi-server setup in CI environment.F"""

    def setUp(self):
        # Initialize the multi-server environment
        logger.info("Setting up multi-server environment...")

        # Configure the output socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.setblocking(False)

        logger.info("Using Docker Compose file: %s", COMPOSE_FILE)
        self.compose_file = COMPOSE_FILE
        self.client = DockerClient(compose_files=[self.compose_file])

        # Build and start the Docker Compose services
        self.client.compose.build(quiet=True)
        self.client.compose.up(detach=True, wait=True)

        logger.info("Multi-server environment setup complete.")

    def tearDown(self):
        # Clean up the multi-server environment
        logger.info("Tearing down multi-server environment...")
        self.client.compose.down()
        logger.info("Teardown complete.")

    def test_multi_server_functionality(self):
        """Test the functionality of the multi-server setup."""
        # Test the basic functionality of the multi-server setup
        logger.info("Testing multi-server functionality...")

        command = "echo 'testpass' | radtest testuser testpass freeradius 0 testing123 || true"

        result = self.client.compose.execute(
            service="radius-client",
            command=["bash", "-c", command],
            tty=False,
            detach=False,
        )

        self.assertIn(
            "Received Access-Accept",
            result,
            "Expected Access-Accept response from the server.",
        )

        logger.info("Multi-server functionality test passed.")


def run_tests(compose_file: Path = None) -> None:
    """Run the test suite for the multi-server setup."""
    logger.info("Running tests for multi-server setup...")
    if compose_file:
        global COMPOSE_FILE
        COMPOSE_FILE = compose_file

    suite = unittest.TestLoader().loadTestsFromTestCase(MultiServerTest)
    unittest.TextTestRunner().run(suite)


if __name__ == "__main__":
    run_tests()
