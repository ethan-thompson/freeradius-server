"""
Validator object
"""

import asyncio
import copy
import logging
import re

from termcolor import colored

logger = logging.getLogger()


class Validator:
    """
    Validator class that will take care of all of the trigger validation
    """

    def __init__(self, rules_map: dict, end_test: asyncio.Future):
        self.__rules_map = rules_map
        self.__rules_tracking = copy.deepcopy(rules_map)
        self.__end_test = end_test

    @property
    def complete(self) -> bool:
        """
        Check if all rules have been matched.

        Returns:
            bool: True if all rules have been matched, False otherwise.
        """
        return self.__rules_tracking == {}

    @property
    def unmatched_rules(self) -> dict:
        """
        Get the rules that have not been matched.

        Returns:
            dict: A dictionary of unmatched rules.
        """
        return self.__rules_tracking

    def get_results_str(self, detailed: bool = False) -> str:
        """
        Get a string representation of the validation results.

        Args:
            detailed (bool, optional): Whether to include matched rules in the output. Defaults to False.

        Returns:
            str: A string representation of the validation results.
        """
        header = "Validation Results\n"
        output = "-" * (len(header) - 1) + "\n"
        output += header
        output += "-" * (len(header) - 1) + "\n"

        total = 0
        matched = 0
        for key, values in self.__rules_map.items():
            flag = False
            key_color = "green"

            if key in self.__rules_tracking:
                key_color = "red"

                if len(self.__rules_tracking[key]) < len(values):
                    key_color = "yellow"

            for value in values:
                total += 1
                if (
                    key in self.__rules_tracking
                    and value in self.__rules_tracking[key]
                ):
                    if flag:
                        output += (
                            f"{' ' * (len(key) + 2)}{colored(value, 'red')}\n"
                        )
                    else:
                        output += f"{colored(key, key_color)}: {colored(value, 'red')}\n"
                        flag = True
                else:
                    matched += 1
                    if detailed:
                        if flag:
                            output += f"{' ' * (len(key) + 2)}{colored(value, 'green')}\n"
                        else:
                            output += f"{colored(key, key_color)}: {colored(value, 'green')}\n"
                            flag = True

        output += "-" * (len(header) - 1) + "\n"
        output += f"Matched: {colored(matched, 'green')} / {total} (Failures: {colored(total - matched, 'red')})\n"
        output += "-" * (len(header) - 1) + "\n"
        return output

    def validate(self, attribute: str, value: str) -> bool:
        """
        Validates a given attribute-value pair against the rules map.

        Args:
            attribute (str): The attribute to validate.
            value (str): The value of the attribute.

        Returns:
            bool: True if the attribute-value pair is valid, False otherwise.
        """
        if attribute in self.__rules_map:
            logger.debug(
                "Validating attribute: %s, value: %s", attribute, value
            )
            logger.debug("Checking rules: %s", self.__rules_map[attribute])
            for pattern in self.__rules_map[attribute]:
                if re.match(pattern, value):
                    if attribute in self.__rules_tracking:
                        # Remove the matched condition
                        self.__rules_tracking[attribute].remove(pattern)

                        # If no more patterns are left for this rule, remove it from tracking
                        if not self.__rules_tracking[attribute]:
                            del self.__rules_tracking[attribute]

                            if self.__rules_tracking == {}:
                                # All rules have been satisfied
                                self.__end_test.set_result(True)
                    return True
        return False
