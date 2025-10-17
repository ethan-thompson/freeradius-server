"""Module to define rules for test validation in a multi-server test environment."""

import re
import logging

# All rule methods should return True if the rule passes, False otherwise.

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
            # return False
    logger.debug("'all' rule passed.")
    return True

def any_pass(
    methods: list[callable], logger: logging.Logger, string: str
) -> bool:
    """
    Check if any of the provided methods return True.

    Args:
        methods (list[callable]): List of functions to be called.
        logger (logging.Logger): Logger for debug output.
        *args: Positional arguments to pass to each method.
        **kwargs: Keyword arguments to pass to each method.

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

def never_fire(
        logger: logging.Logger, *args, **kwargs
) -> bool:
    """
    A rule that should never pass.

    Args:
        logger (logging.Logger): Logger for debug output.
        *args: Positional arguments (not used).
        **kwargs: Keyword arguments (not used).

    Returns:
        bool: Always returns False.
    """
    logger.debug("Evaluating 'never_fire' rule, which always fails.")
    return False

def pattern(
    reg_pattern: str | re.Pattern[str], logger: logging.Logger, string: str
) -> bool:
    """
    Check if a string matches a given regex pattern.

    Args:
        pattern (str | re.Pattern[str]): The regex pattern to match against.
        string (str): The string to be checked.
        logger (logging.Logger): Logger for debug output.

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

def within_range(
        minimum: float, maximum: float, logger: logging.Logger, string: float | str
) -> bool:
    """
    Check if a number is within a specified range.

    Args:
        minimum (float): The minimum value of the range.
        maximum (float): The maximum value of the range.
        number (float | str): The number to be checked.
        logger (logging.Logger): Logger for debug output.

    Returns:
        bool: True if the number is within the range, False otherwise.
    """
    logger.debug("Checking if number is within range: %f - %f", minimum, maximum)
    logger.debug("Number to check: %s", string)

    if isinstance(string, str):
        try:
            string_parts = string.split(':')
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

def rule_methods() -> dict[str, callable]:
    """
    Returns a dictionary of available rule methods.

    Returns:
        dict[str, callable]: A dictionary mapping rule names to their corresponding functions.
    """
    return {
        "pattern": pattern,
        "regex": pattern,
        "range": within_range,
        "within_range": within_range,
        "fail": never_fire,
        "never_fire": never_fire,
    }

def control_methods() -> dict[str, callable]:
    """
    Returns a dictionary of control methods for combining rules.

    Returns:
        dict[str, callable]: A dictionary mapping control names to their corresponding functions.
    """
    return {
        "all": all_pass,
        "any": any_pass,
        "all_pass": all_pass,
        "any_pass": any_pass,
    }
