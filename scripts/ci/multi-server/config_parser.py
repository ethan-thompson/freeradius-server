"""config_parser.py
Configuration parser for multi-server setup
This script is used to parse configuration files
for a multi-server test, and generates two output files:
    1. `docker-compose.yml` for Docker Compose setup
    2. `test-config.yml` for test configuration
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Tuple
import jinja2
import yaml


class NoQuotedMergeDumper(yaml.SafeDumper):
    """
    Custom YAML dumper that avoids quoting merge keys (<<).
    """


def no_quoted_merge_key(dumper, data):
    """
    Custom representer to avoid quoting merge keys (<<).
    """
    if data == "<<":
        return dumper.represent_scalar(
            "tag:yaml.org,2002:merge", data, style=""
        )
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)

# Register the custom representer
NoQuotedMergeDumper.add_representer(str, no_quoted_merge_key)


def _parse_config(config: dict) -> Tuple[dict, dict]:
    """
    Parses a configuration dictionary and separates the compose and test configurations.
    Args:
        config (dict): The configuration dictionary.
    Returns:
        Tuple[dict, dict]: A tuple containing two dictionaries:
            - 'compose_configs': A dictionary of compose configurations.
            - 'other_configs': A dictionary of other configurations.
    """
    compose_configs = {}
    other_configs = {}

    for key, value in config.items():
        if key.startswith("fixtures"):
            # Start by adding the default capabilities to the compose configs
            default_capabilities = {"cap_add": ["NET_ADMIN", "SYS_PTRACE"]}
            compose_configs["x-common-config"] = default_capabilities

            for compose_key, compose_value in value.items():
                if compose_key.startswith(tuple(["services", "hosts"])):
                    # compose_configs["services"] = compose_value
                    updated_services = {}
                    for service_name, service_config in compose_value.items():
                        service_config["<<"] = default_capabilities
                        updated_services[service_name] = service_config
                    compose_configs["services"] = updated_services
                else:
                    compose_configs["services"] = compose_value
        else:
            other_configs[key] = value

    return compose_configs, other_configs


def generate_config_files(
    file_path: Path,
    compose_output: Path = Path(Path(__file__).parent, "docker-compose.yml"),
    test_output: Path = Path(Path(__file__).parent, "test-config.yml"),
) -> None:
    """
    Generates configuration files for multi-server setup.

    Args:
        file_path (Path): The path to the configuration file.
        compose_output (Path, optional): The path to output the Docker Compose file.
            Defaults to 'docker-compose.yml' in the current directory.
        test_output (Path, optional): The path to output the test configs.
            Defaults to 'test-config.yml' in the current directory.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If the configuration file has an unsupported file type.
    """
    # If the config file does not exist, raise an error
    if not file_path.exists():
        raise FileNotFoundError(
            f"Configuration file {file_path} does not exist."
        )

    # If the config file is already rendered, just parse it
    if file_path.suffix == ".yml":
        with open(file_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
    elif file_path.suffix == ".j2":
        # If the config file is a Jinja2 template, render it
        template_loader = jinja2.FileSystemLoader(searchpath=file_path.parent)
        template_env = jinja2.Environment(loader=template_loader)
        template_env.globals.update(
            os=os,
        )
        template = template_env.get_template(file_path.name)
        rendered_config = template.render()
        config = yaml.safe_load(rendered_config)
    else:
        raise ValueError(
            "Unsupported file type. Only .yml and .j2 are supported."
        )

    # Parse the configuration
    compose_configs, other_configs = _parse_config(config)

    # Write the compose configurations to docker-compose.yml if there are any
    if compose_configs:
        with open(compose_output, "w", encoding="utf-8") as compose_file:
            yaml.dump(
                compose_configs,
                compose_file,
                default_flow_style=False,
                sort_keys=False,
                Dumper=NoQuotedMergeDumper,
            )

    # Write the other configurations to test-config.yml if there are any
    if other_configs:
        with open(test_output, "w", encoding="utf-8") as test_config_file:
            yaml.dump(
                other_configs,
                test_config_file,
                default_flow_style=False,
                sort_keys=False,
                Dumper=NoQuotedMergeDumper,
            )


def parse_args(args=None, prog=__package__) -> argparse.Namespace:
    """
    Parses command line arguments for the configuration parser.
    Args:
        args (list, optional): List of command line arguments. Defaults to None.
        prog (str, optional): Program name. Defaults to the package name.
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Generate configuration docker and test files for multi-server setup.",
    )
    parser.add_argument(
        "config_file", type=str, help="Path to the configuration file."
    )
    parser.add_argument(
        "--compose_output",
        dest="compose_output",
        type=str,
        help="Path to output the Docker Compose file.",
        default=Path(Path(__file__).parent, "docker-compose.yml"),
    )
    parser.add_argument(
        "--test_output",
        dest="test_output",
        type=str,
        help="Path to output the test configs.",
        default=Path(Path(__file__).parent, "test_configs.yml"),
    )
    return parser.parse_args(args)


if __name__ == "__main__":
    parsed_args = parse_args()

    try:
        generate_config_files(
            Path(parsed_args.config_file),
            Path(parsed_args.compose_output),
            Path(parsed_args.test_output),
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("Configuration files generated successfully.")
    sys.exit(0)
