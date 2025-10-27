"""Module to define rules for test validation in a multi-server test environment."""

import re
import logging

# All rule methods should return True if the rule passes, False otherwise.

CONTROL_MAP = {}  # A mapping of control rule names to their functions.
RULES_MAP = {}  # A mapping of rule names to their functions.


class SingleRuleFailure(Exception):
    """Exception raised when a single rule fails from a set of rules."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def all_pass(
    methods: list[callable], logger: logging.Logger, string: str
) -> bool:
    """
    Check if all provided methods return True.

    Args:
        methods (list[callable]): List of functions to be called.
        logger (logging.Logger): Logger for debug output.
        string (str): The string to be validated.

    Returns:
        bool: True if all methods return True, False otherwise.

    Raises:
        SingleRuleFailure: If any method returns False.
    """

    logger.debug("Evaluating 'all' rule with %d methods.", len(methods))
    for method in methods:
        if not method(string):
            logger.debug("'all' rule failed on method: %s", method.__name__)
            raise SingleRuleFailure(f"all: {method.friendly_str}")
    logger.debug("'all' rule passed.")
    return True


CONTROL_MAP.update({"all_pass": all_pass, "all": all_pass})


def any_pass(
    methods: list[callable], logger: logging.Logger, string: str
) -> bool:
    """
    Check if any of the provided methods return True.

    Args:
        methods (list[callable]): List of functions to be called.
        logger (logging.Logger): Logger for debug output.
        string (str): The string to be validated.

    Returns:
        bool: True if any method returns True, False otherwise.
    """
    logger.debug("Evaluating 'any' rule with %d methods.", len(methods))
    for method in methods:
        if method(string):
            logger.debug("'any' rule passed on method: %s", method.__name__)
            return True
    logger.debug("'any' rule failed.")
    return False


CONTROL_MAP.update({"any_pass": any_pass, "any": any_pass})


def never_fire(logger: logging.Logger, string: str) -> bool:
    """
    A rule that should never pass.

    Args:
        logger (logging.Logger): Logger for debug output.
        string (str): The string to be validated.

    Returns:
        bool: Always returns False.
    """
    logger.debug("Evaluating 'never_fire' rule, which always fails.")
    return False


RULES_MAP.update({"never_fire": never_fire, "fail": never_fire})


def pattern(
    reg_pattern: str | re.Pattern[str], logger: logging.Logger, string: str
) -> bool:
    """
    Check if a string matches a given regex pattern.

    Args:
        pattern (str | re.Pattern[str]): The regex pattern to match against.
        logger (logging.Logger): Logger for debug output.
        string (str): The string to be checked.

    Returns:
        bool: True if the string matches the pattern, False otherwise.
    """
    if isinstance(reg_pattern, str):
        reg_pattern = re.compile(reg_pattern)

    match = reg_pattern.match(string)
    if match:
        logger.debug("Pattern matched: %s", reg_pattern.pattern)
        return True
    logger.debug("Pattern did not match: %s", reg_pattern.pattern)
    return False


RULES_MAP.update({"pattern": pattern, "regex": pattern})


def within_range(
    minimum: float, maximum: float, logger: logging.Logger, string: float | str
) -> bool:
    """
    Check if a number is within a specified range.

    Args:
        minimum (float): The minimum value of the range.
        maximum (float): The maximum value of the range.
        logger (logging.Logger): Logger for debug output.
        string (float | str): The number to be checked.

    Returns:
        bool: True if the number is within the range, False otherwise.
    """
    logger.debug(
        "Checking if number is within range: %f - %f", minimum, maximum
    )
    logger.debug("Number to check: %s", string)

    if isinstance(string, str):
        try:
            string_parts = string.split(":")
            if len(string_parts) == 1:
                string = float(string_parts[0])
            else:
                string = float(string_parts[1])
        except ValueError:
            logger.debug("Provided value is not a valid float: %s", string)
            return False

    if minimum <= string <= maximum:
        logger.debug("Number is within range: %f", string)
        return True
    logger.debug("Number is out of range: %f", string)
    return False


RULES_MAP.update({"range": within_range, "within_range": within_range})


def is_code_safe(_source: str, logger: logging.Logger) -> bool:
    """
    Check if the provided code block is safe to execute.

    Args:
        _source (str): The code block to check.
        logger (logging.Logger): Logger for debug output.
    Returns:
        bool: True if the code is safe, False otherwise.
    """
    logger.warning(
        "Code safety check is not implemented. Proceeding without checks."
    )
    return True


def code(block: str, logger: logging.Logger, string: str) -> bool:
    """
    Execute a custom code block for validation.

    Args:
        block (str): The code block to execute.
        logger (logging.Logger): Logger for debug output.
        string (str): The string to be validated.

    Returns:
        bool: The result of the executed code block.
    """
    logger.debug("Evaluating custom code block.")
    if not is_code_safe(block, logger):
        logger.error("Unsafe code block detected. Execution aborted.")
        return False

    logger.debug("Executing custom code block.")

    indented_block = "\n".join(f"    {line}" for line in block.splitlines())
    wrapped_code = f"def _wrapped_func():\n{indented_block}"

    local_vars = {"string": string, "logger": logger}
    try:
        exec(wrapped_code, local_vars)
        result = local_vars.get("_wrapped_func", lambda: False)()
        logger.debug("Custom code block executed with result: %s", result)
        return result
    except Exception as e:
        logger.error("Error executing custom code block: %s", e)
        return False


RULES_MAP.update({"code": code})


def rule_methods() -> dict[str, callable]:
    """
    Returns a dictionary of available rule methods.

    Returns:
        dict[str, callable]: A dictionary mapping rule names to their corresponding functions.
    """
    return RULES_MAP


def control_methods() -> dict[str, callable]:
    """
    Returns a dictionary of control methods for combining rules.

    Returns:
        dict[str, callable]: A dictionary mapping control names to their corresponding functions.
    """
    return CONTROL_MAP
