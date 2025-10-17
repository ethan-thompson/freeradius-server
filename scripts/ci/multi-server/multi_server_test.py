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
from termcolor import colored

from events import (  # pylint: disable=import-error
    NetworkEvents,
    RADIUSEvents,
    CommandEvents,
)

from state import State  # pylint: disable=import-error
from custom_test import (  # pylint: disable=import-error
    Test,
    create_test_logger,
)
import rules  # pylint: disable=import-error

DEBUG_LEVEL = 0
VERBOSE_LEVEL = 0

# Add a log handler for the INFO level
info_handler = logging.StreamHandler(sys.stdout)
info_handler.setLevel(logging.INFO)
info_handler.addFilter(lambda record: record.levelno == logging.INFO)
info_handler.setFormatter(logging.Formatter("%(message)s"))

debug_handler = logging.StreamHandler(sys.stderr)
debug_handler.setLevel(logging.DEBUG)
debug_handler.addFilter(lambda record: record.levelno == logging.DEBUG)
debug_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)

# Create a handler that will make all Warning messages yellow
warning_handler = logging.StreamHandler(sys.stderr)
warning_handler.setLevel(logging.WARNING)
warning_handler.addFilter(lambda record: record.levelno == logging.WARNING)
warning_handler.setFormatter(
    logging.Formatter(
        colored(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", "yellow"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)

# Create a handler that will make all Error messages red
error_handler = logging.StreamHandler(sys.stderr)
error_handler.setLevel(logging.ERROR)
error_handler.addFilter(lambda record: record.levelno >= logging.ERROR)
error_handler.setFormatter(
    logging.Formatter(
        colored("%(asctime)s - %(name)s - %(levelname)s - %(message)s", "red"),
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add the handlers to the logger
logger.addHandler(info_handler)
logger.addHandler(error_handler)
logger.addHandler(warning_handler)


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
        logger.debug("Cancelling task: %s", task.get_name())
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.debug("Cleanup completed.")

    logger.debug("Stopping the event loop...")
    # Stop the event loop if it's running
    if asyncio.get_event_loop().is_running():
        asyncio.get_event_loop().stop()
    logger.debug("Event loop stopped.")

def build_rule(condition: str, params: dict) -> callable:
    """
    Build a rule function that can be used to validate events.

    Args:
        condition (str): The condition to build the rule for.
        params (dict): The parameters for the condition.

    Returns:
        callable: A function that takes a string and returns True if the rule passes, False otherwise.
    """
    known_rules = rules.rule_methods()
    controls = rules.control_methods()

    if condition in known_rules:
        func = known_rules[condition]
        rule_params = params

        method = lambda x: func(**rule_params, logger=logging.getLogger("__main__"), string=x)
        method.rule_params = rule_params
        method.friendly_str = f"{condition}: {', '.join(f'{k}={v}' for k, v in rule_params.items())}"

        return method

    if condition in controls:
        func = controls[condition]

        methods = []

        for sub_condition in params.keys():
            logger.debug("Sub-condition: %s", sub_condition)
            methods.append(build_rule(sub_condition, params[sub_condition]))

        logger.debug("Control methods: %s", methods)

        method = lambda x: func(methods=methods, logger=logging.getLogger("__main__"), string=x)
        method.rule_params = {"methods": methods}
        method.friendly_str = f"{condition}: {', '.join(m.friendly_str for m in methods)}"

        return method

    return lambda x: False

def generate_rules_map(state: dict) -> dict:
    """
    Generate a mapping of triggers to their corresponding validation functions.
    Returns:
        dict: A mapping of triggers to validation functions.
    """

    rules_map = {}
    for trigger in state.get("verify", {}).get("triggers", []):
        trigger_name = list(trigger.keys())[0]

        try:
            for condition in list(trigger.get(trigger_name, {})):
                logger.info("Condition: %s", condition)
                if trigger_name not in rules_map:
                    rules_map[trigger_name] = []
                rules_map[trigger_name].append(build_rule(condition, trigger.get(trigger_name, {}).get(condition, {})))
                logger.info(
                    "Added rule for trigger %s: %s", trigger_name, condition
                )
        except Exception as e:
            logger.error(
                "Error adding rule for trigger %s: %s", trigger_name, e
            )
            continue
    return rules_map


def parse_test_configs(
    config: Path | dict, test_name: str
) -> tuple[float, list[dict]]:
    """
    Parse the test configuration file.

    Args:
        config (Path | dict): Path to the configuration file or a dictionary containing the config.
        test_name (str): Name of the test.

    Returns:
        float: Timeout for the test.
        list[dict]: List of state configurations. Each state configuration is a dictionary
            with keys:
            - name (str): Name of the state.
            - description (str): Description of the state.
            - timeout (int): Timeout for the state.
            - actions (list[callable]): List of actions to perform in the state.
            - rules_map (dict): Mapping of triggers to validation patterns.

    Raises:
        ValueError: If the configuration file is invalid.
    """

    logger.info("Parsing test configuration file: %s", config)

    # Verify the file exists
    if isinstance(config, Path) and not config.exists():
        logger.error("Configuration file does not exist: %s", config)
        return []

    known_actions = {}

    for event_class in [RADIUSEvents, NetworkEvents, CommandEvents]:
        events = event_class.get_events()
        known_actions.update(events)

    raw_configs = {}

    if isinstance(config, Path):
        with open(config, "r", encoding="utf-8") as f:
            raw_configs = yaml.safe_load(f)
    else:
        raw_configs = config

    timeout: float = raw_configs.get("timeout", 40.0)
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
                        params["source"] = f"{test_name}-{host}-1"

                    # if the function takes a target parameter, update it
                    if "target" in func.__code__.co_varnames:
                        if "target" not in params:
                            raise ValueError(
                                f"Action {action_name} requires a target parameter."
                            )
                        # Update the target to include the full container name
                        params["target"] = f"{test_name}-{params['target']}-1"

                    # if the function takes a test_name parameter, add it
                    if "test_name" in func.__code__.co_varnames:
                        params["test_name"] = test_name

                    # If the function takes a logger parameter, set a default logger
                    if "logger" in func.__code__.co_varnames:
                        return lambda logger=logging.getLogger(
                            "__main__"
                        ): func(**params, logger=logger)
                    return lambda: func(**params)

                action_params = action.get(action_name, {})
                actions.append(build_action(action_func, action_params, host))

        # Parse the rules map
        # TODO: Handle ordered vs unordered triggers
        # trigger_mode = state.get("verify", {}).get("trigger_mode", "unordered")
        rules_map = generate_rules_map(state=state)

        state_config["actions"] = actions
        state_config["rules_map"] = rules_map

        configs.append(state_config)
    return timeout, configs


def generate_states(
    loop: asyncio.AbstractEventLoop,
    config: Path | dict,
    test_name: str,
    test_logger: logging.Logger,
) -> tuple[float, list[State]]:
    """
    Generate a list of states for testing.

    Args:
        loop (asyncio.AbstractEventLoop): The event loop to use.
        config (Path | dict): Path to the configuration file or a dictionary
          containing the config.

    Returns:
        timeout (float): Timeout for the test.
        states (list[State]): List of State objects created from the configuration.

    Raises:
        ValueError: If the configuration file is invalid.
    """
    try:
        timeout, state_configs = parse_test_configs(config, test_name)
    except ValueError as e:
        raise ValueError(f"Invalid configuration file: {e}") from e

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
                logger=test_logger,
            )
        )
    return timeout, states


def build_tests(
    loop: asyncio.AbstractEventLoop, config: Path | dict, compose_file: Path
) -> list[Test]:
    """
    Build a list of Test objects from the configuration.

    Args:
        loop (asyncio.AbstractEventLoop): The event loop to use.
        config (Path | dict): Path to the configuration file/directory or a dictionary
          containing the config.

    Returns:
        list[Test]: List of Test objects.

    Raises:
        ValueError: If the configuration is invalid.
    """
    logger.debug("Building tests")

    tests = []

    if isinstance(config, Path) and config.is_dir():
        for test_file in config.glob("*.yml"):
            test_name = test_file.stem
            test_logger = create_test_logger(test_name)
            try:
                timeout, states = generate_states(
                    loop, test_file, test_name, test_logger
                )
                tests.append(
                    Test(
                        name=test_name,
                        states=states,
                        compose_file=compose_file,
                        timeout=timeout,
                        detail_level=VERBOSE_LEVEL,
                        loop=loop,
                        logger=test_logger,
                    )
                )
            except ValueError as e:
                logger.error("Invalid configuration in %s: %s", test_file, e)
                logger.debug("Skipping invalid test configuration.")
    else:
        try:
            test_name = "custom_test"
            test_logger = create_test_logger(test_name)
            timeout, states = generate_states(
                loop, config, test_name, test_logger
            )
            tests.append(
                Test(
                    name=test_name,
                    states=states,
                    compose_file=compose_file,
                    timeout=timeout,
                    detail_level=VERBOSE_LEVEL,
                    loop=loop,
                    logger=test_logger,
                )
            )
        except ValueError as e:
            raise ValueError(f"Invalid configuration: {e}") from e

    return tests


async def run_tests(tests: list[Test]) -> None:
    """
    Run the provided tests.

    Args:
        tests (list[Test]): List of Test objects to run.
    """
    try:
        async with asyncio.TaskGroup() as tg:
            for test in tests:
                tg.create_task(test.run(VERBOSE_LEVEL == 3))
    except Exception as e:
        logger.error("An error occurred while running tests: %s", e)

    logger.info("All tests completed.")


def main(compose_file: Path, configs: Path | dict) -> None:
    """
    Main function to run the multi-server tests.

    Args:
        compose_file (Path): Path to the Docker Compose file.
        configs (Path | dict): Path to the test configuration file or a dictionary
            containing the config.
    """
    # Run a test in an asynchronous event loop
    loop = asyncio.get_event_loop()

    try:
        # Add a signal handler to gracefully handle shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(cleanup_and_shutdown())
            )

        # Generate the states from the config
        tests = build_tests(loop, configs, compose_file)

        # Create the test task group
        test_task = loop.create_task(run_tests(tests))

        # Start the shutdown when the test completes
        test_task.add_done_callback(
            lambda _: asyncio.create_task(cleanup_and_shutdown())
        )

        # Run the event loop until all tasks are complete
        loop.run_forever()
    except Exception as e:
        logger.error("An error occurred while running tests: %s", e)
    finally:
        logger.debug("Closing the event loop...")
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
        "-t",
        "--test",
        dest="test",
        type=Path,
        help="Path to the test configuration file.",
        default=Path(Path(__file__).parent, "tests"),
    )
    parser.add_argument(
        "--filter",
        dest="filter",
        type=str,
        help="Filter test logs by name. Format is a comma separated list of test names.",
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
        logger.addHandler(debug_handler)
        DEBUG_LEVEL = parsed_args.debug
        logger.info("Debug mode enabled. Debug level: %d", DEBUG_LEVEL)

    if parsed_args.verbose:
        VERBOSE_LEVEL = parsed_args.verbose
        logger.info("Verbose mode enabled. Verbose level: %d", VERBOSE_LEVEL)

    if parsed_args.filter:
        filter_names = [
            f"Test.{name.strip()}" for name in parsed_args.filter.split(",")
        ]

        # Add a filter to the logger to only show messages that contain the filter string
        class FilterByName(logging.Filter):
            """
            Filter log records by name.
            """

            def filter(self, record: logging.LogRecord) -> bool:
                return record.name in filter_names

        logger.addFilter(FilterByName())
        for handler in logger.handlers:
            handler.addFilter(FilterByName())
        logger.info("Filtering logs by name: %s", parsed_args.filter)

    if parsed_args.config_file:
        try:
            # Generate the compose and test config files
            from config_parser import (  # pylint: disable=import-error
                generate_configs,
                write_yaml_to_file,
            )

            compose_configs, test_configs = generate_configs(
                Path(parsed_args.config_file)
            )
        except (FileNotFoundError, ValueError) as e:
            logger.error("Error generating config files: %s", e)
            sys.exit(1)

        if compose_configs:
            write_yaml_to_file(
                compose_configs,
                Path(Path(__file__).parent, "docker-compose.yml"),
            )
        if test_configs:
            main(
                compose_file=Path(Path(__file__).parent, "docker-compose.yml"),
                configs=test_configs,
            )
        else:
            main(
                compose_file=Path(Path(__file__).parent, "docker-compose.yml"),
                configs=parsed_args.test,
            )

    else:
        main(compose_file=parsed_args.compose_file, configs=parsed_args.test)
