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

import yaml
from python_on_whales import DockerClient

from events import (  # pylint: disable=import-error
    NetworkEvents,
    RADIUSEvents,
    CommandEvents,
)

from state import State  # pylint: disable=import-error

DEBUG_LEVEL = 0
VERBOSE_LEVEL = 0

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
    msg_queue: asyncio.Queue,
) -> None:
    """
    Handles incoming client connections and processes messages.

    Args:
        reader (asyncio.StreamReader): Reader for the incoming data.
        writer (asyncio.StreamWriter): Writer for sending responses.
        msg_queue (asyncio.Queue, optional): Queue to put received messages into.
    """
    logger.debug("Client connected.")
    try:
        while True:
            data = await reader.readuntil(b"\n")
            message = data.decode().strip()
            logger.debug("Received message: %s", message)

            trigger_name, trigger_value = message.split(" ", 1)

            msg_queue.put_nowait((trigger_name, trigger_value))

    except Exception as e:
        logger.error("Error handling client: %s", e)
    finally:
        writer.close()
        await writer.wait_closed()
        logger.debug("Client disconnected.")


async def unix_server(
    socket_path: Path,
    msg_queue: asyncio.Queue,
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
            lambda r, w: handle_client(r, w, msg_queue),
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
    test_timeout: float,
    msg_queue: asyncio.Queue,
    states: list[State],
    loop: asyncio.AbstractEventLoop,
) -> None:
    """
    Runs tests in a multi-server setup using Docker Compose.

    Args:
        compose_file (Path): Path to the Docker Compose file.
        ready_future (asyncio.Future): Future to signal when the server is ready.
        test_timeout (float): Timeout for the entire test run.
        msg_queue (asyncio.Queue): Queue to receive messages from the server.
        states (list[State]): List of states to process during the test.
        loop (asyncio.AbstractEventLoop): The event loop to use.
    """
    if not ready_future.done():
        logger.debug("Waiting for server to be ready...")
        await ready_future

    logger.info("Running tests with compose file: %s", compose_file)

    # Build the Docker Compose services
    client = DockerClient(compose_files=[compose_file])
    client.compose.build(quiet=True)

    # Start the Docker Compose services
    client.compose.up(detach=True, quiet=True)

    # Set the teardown when the test is finished
    def teardown_containers() -> None:
        logger.info("Tearing down Docker Compose services...")
        client.compose.down(quiet=True)
        logger.info("Docker Compose services stopped.")

    test_finished = loop.create_future()
    test_finished.add_done_callback(lambda _: teardown_containers())

    # Setup the teardown in case of timeout
    def on_timeout() -> None:
        logger.info("Test timeout reached.")
        if not test_finished.done():
            test_finished.set_result(True)

    loop.call_later(test_timeout, on_timeout)

    logger.info("Docker Compose services started.")

    logger.info("Waiting for services to initialize...")
    await asyncio.sleep(2)

    logger.info("Running simulated tests...")

    validation_task: asyncio.Task = None
    for state in states:
        logger.debug(
            "Processing state: %s - %s", state.name, state.description
        )
        logger.debug("Entering state with %d actions.", len(state.actions))

        # Register new validator for state
        # First, clear the message queue
        logger.debug("Clearing message queue...")
        while not msg_queue.empty():
            msg_queue.get_nowait()

        # Next, setup the validator to use the message queue
        logger.debug("Setting up validator for state...")
        if validation_task:
            # Swap out the previous validation task
            validation_task.cancel()
            try:
                await validation_task
            except asyncio.CancelledError:
                pass
        validation_task = loop.create_task(
            state.validator.start_validating(msg_queue)
        )

        # Enter the state
        logger.debug("Entering state...")
        await state.enter_state()

        # Wait for the state to complete
        logger.debug("Waiting for state to complete...")
        await state.wait_for_completion()
        logger.debug("State completed.")
        # end_test.set_result(True)

        # Print the validation results
        logger.info(state.validator.get_results_str(VERBOSE_LEVEL))

    if not test_finished.done():
        # Set the test as finished and trigger the teardown callback
        test_finished.set_result(True)


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


def parse_test_configs(config: Path | dict) -> list[dict]:
    """
    Parse the test configuration file.

    Args:
        config (Path | dict): Path to the configuration file or a dictionary containing the config.

    Returns:
        list[dict]: List of state configurations. Each state configuration is a dictionary with keys:
            - name (str): Name of the state.
            - description (str): Description of the state.
            - timeout (int): Timeout for the state.
            - actions (list[callable]): List of actions to perform in the state.
            - rules_map (dict): Mapping of triggers to validation patterns.
    """

    logger.info("Parsing test configuration file: %s", config)

    # Verify the file exists
    if isinstance(config, Path) and not config.exists():
        logger.error("Configuration file does not exist: %s", config)
        return []

    # TODO: Build this automatically
    known_actions = {
        "access_request": RADIUSEvents.access_request,
        "network_disconnect": NetworkEvents.disconnect,
        "network_reconnect": NetworkEvents.reconnect,
        "packet_loss": NetworkEvents.packet_loss,
        "execute_command": CommandEvents.run_command,
        "command": CommandEvents.run_command,
    }

    raw_configs = {}

    if isinstance(config, Path):
        with open(config, "r", encoding="utf-8") as f:
            raw_configs = yaml.safe_load(f)
    else:
        raw_configs = config

    configs = []
    for state_name, state in raw_configs.get("states", {}).items():
        state_config = {}

        state_config["name"] = state_name
        state_config["description"] = state.get("description", "")
        state_config["timeout"] = state.get("verify", []).get("timeout", 15)

        # Parse the actions
        actions = []
        for host, host_config in state.get("host", {}).items():
            for action in host_config.get("actions", []):
                action_name = list(action.keys())[0]
                if action_name not in known_actions:
                    logger.warning("Unknown action: %s", action_name)
                    continue

                action_func = known_actions[action_name]

                # Build the action with its parameters
                def build_action(func, params, host):
                    # if the function takes a source parameter, add it
                    if "source" in func.__code__.co_varnames:
                        params["source"] = host

                    return lambda: func(**params)

                action_params = action.get(action_name, {})
                actions.append(build_action(action_func, action_params, host))

        # Parse the rules map
        # TODO: Handle ordered vs unordered triggers
        # trigger_mode = state.get("verify", {}).get("trigger_mode", "unordered")
        rules_map = {}
        for trigger in state.get("verify", {}).get("triggers", []):
            trigger_name = list(trigger.keys())[0]
            pattern = trigger.get(trigger_name, {}).get("pattern", None)
            if not pattern:
                logger.warning("No pattern for trigger: %s", trigger_name)
                continue

            if trigger_name not in rules_map:
                rules_map[trigger_name] = []

            rules_map[trigger_name].append(pattern)

        state_config["actions"] = actions
        state_config["rules_map"] = rules_map

        configs.append(state_config)
    return configs


def generate_states(loop: asyncio.AbstractEventLoop) -> list[State]:
    """
    Generate a list of states for testing.

    Args:
        loop (asyncio.AbstractEventLoop): The event loop to use.

    Returns:
        list[State]: List of states to be used in the test.
    """
    # return [
    #     State(
    #         actions=[
    #             lambda: RADIUSEvents.access_request(
    #                 source="radius-client",
    #                 target="freeradius",
    #                 secret="testing123",
    #                 username="testuser",
    #                 password="testpass",
    #             )
    #         ],
    #         rules_map={"request_sent": [r"(\w+) request sent"]},
    #         loop=loop,
    #     ),
    #     State(
    #         actions=[
    #             lambda: NetworkEvents.packet_loss(
    #                 targets=["freeradius"],
    #                 interface="eth0",
    #                 loss=100.00,
    #             ),
    #             lambda: RADIUSEvents.access_request(
    #                 source="radius-client",
    #                 target="freeradius",
    #                 secret="testing123",
    #                 username="testuser",
    #                 password="testpass",
    #             ),
    #         ],
    #         rules_map={
    #         },
    #         loop=loop,
    #     ),
    # ]
    config_file = Path(__file__).parent / "test_configs.yml"
    state_configs = parse_test_configs(config_file)
    states = []
    for state_config in state_configs:
        states.append(
            State(
                name=state_config.get("name", "Unnamed State"),
                description=state_config.get("description", ""),
                actions=state_config.get("actions", []),
                rules_map=state_config.get("rules_map", {}),
                timeout=state_config.get("timeout", 15),
                loop=loop,
            )
        )
    return states


def main(compose_file: Path) -> None:
    """
    Main function to run the multi-server tests.

    Args:
        compose_file (Path): Path to the Docker Compose file.
    """
    # Run a test in an asynchronous event loop
    loop = asyncio.get_event_loop()

    # TODO: Pull this from the config
    timeout = 40

    try:
        # Set up the Unix server
        output_socket = Path("/var/run/multi-test/test.sock")
        ready_future = loop.create_future()

        msg_queue: asyncio.Queue = asyncio.Queue()

        loop.create_task(unix_server(output_socket, msg_queue, ready_future))

        # Add a signal handler to gracefully handle shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(cleanup_and_shutdown())
            )

        states = generate_states(loop)

        # Run the tests
        test_task = loop.create_task(
            run_tests(
                compose_file, ready_future, timeout, msg_queue, states, loop
            )
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
        "-c",
        "--config",
        dest="config_file",
        type=str,
        help="Path to the configuration file.",
        default=None,
    )
    parser.add_argument(
        "--debug",
        "-x",
        dest="debug",
        action="count",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        dest="verbose",
        action="count",
        help="Enable verbose logging.",
    )
    return parser.parse_args(args)


if __name__ == "__main__":
    parsed_args = parse_args()

    if parsed_args.debug:
        logging.getLogger(__name__).setLevel(logging.DEBUG)
        logger.addHandler(not_info_handler)
        DEBUG_LEVEL = parsed_args.debug
        logger.info("Debug mode enabled. Debug level: %d", DEBUG_LEVEL)

    if parsed_args.verbose:
        VERBOSE_LEVEL = parsed_args.verbose
        logger.info("Verbose mode enabled. Verbose level: %d", VERBOSE_LEVEL)

    if parsed_args.config_file:
        try:
            # Generate the compose and test config files
            from config_parser import generate_config_files  # pylint: disable=import-error

            generate_config_files(Path(parsed_args.config_file))
        except (FileNotFoundError, ValueError) as e:
            logger.error("Error generating config files: %s", e)
            sys.exit(1)

    main(compose_file=parsed_args.compose_file)
