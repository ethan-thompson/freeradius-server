"""
Validator object
"""

import asyncio
import copy
import logging
import re

from termcolor import colored


class Validator:
    """
    Validator class that will take care of all of the trigger validation
    """

    def __init__(
        self,
        rules_map: dict,
        state_completed: asyncio.Future,
        logger: logging.Logger = logging.getLogger("__main__"),
    ) -> None:
        self.__rules_map = rules_map
        self.__rules_tracking = copy.deepcopy(rules_map)
        self.__state_completed = state_completed
        self.__logger = logger

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
            detailed (bool, optional): Whether to include matched rules in the output.
                Defaults to False.

        Returns:
            str: A string representation of the validation results.
        """
        header = "Validation Results\n"
        output = "\n"
        output += "-" * (len(header) - 1) + "\n"
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
        output += f"Matched: {colored(matched, 'green')} / {total} "
        output += f"(Failures: {colored(total - matched, 'red')})\n"
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
        if attribute not in self.__rules_map:
            self.__logger.debug("No validation rules for attribute: %s", attribute)
            return False

        self.__logger.debug("Validating attribute: %s, value: %s", attribute, value)
        self.__logger.debug("Checking rules: %s", self.__rules_map[attribute])
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
                            self.__logger.info(
                                "All validation rules have been satisfied."
                            )
                            if not self.__state_completed.done():
                                self.__state_completed.set_result(True)
                return True
        return False

    async def start_validating(self, msg_queue: asyncio.Queue) -> None:
        """
        Start validating events from the msg_queue.

        Args:
            msg_queue (asyncio.Queue): The msg_queue to get messages from.
        """
        while not self.complete and not self.__state_completed.done():
            try:
                msg = await asyncio.wait_for(msg_queue.get(), timeout=None)
                self.__logger.debug(
                    "Validating message with trigger: %s and value: %s",
                    msg[0],
                    msg[1],
                )
                result = self.validate(msg[0], msg[1])

                self.__logger.debug(
                    "Message validation result: %s",
                    colored(
                        "PASSED" if result else "FAILED",
                        "green" if result else "red",
                    ),
                )
            except asyncio.TimeoutError:
                continue

        self.__logger.debug("Validator finished processing messages.")
