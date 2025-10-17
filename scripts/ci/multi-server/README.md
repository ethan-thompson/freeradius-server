# HOW-TO
To use this tool, you first need to generate a docker image on your host by running `docker build -t fr-build-ubuntu22 -f scripts/docker/build/ubuntu22/Dockerfile .` from the project root.

Next, generate the compose and config files using `python3 scripts/ci/multi-server/config_parser.py scripts/ci/multi-server/example.yml.j2`.

You can then run the containers and test by running `python3 foo.py` in one window (this starts a unix server that listens for connections and echos the messages) and then `docker compose -f scripts/ci/multi-server/docker-compose.yml up freeradius`

# Command Arguments
`-c`, `--config` - Path to a configuration file. This file can contain the test configs, compose configs, or both, and can be in either yaml or jinja2 format.

`--compose_file` - Path to the Docker compose file to be used for testing. Defaults to the script source folder in `docker-compose.yml`.

`-t`, `--test` - Path to the test configuration file. Defaults to the directory in the script folder named `tests`.

`--filter` - Filter test logs by name. Format is a comma separated list of test names.

`--debug`, `-x` - Enable debug output.

`--verbose`, `-v` - Enable verbose logging. More "v"'s set a higher verbose level.

# Note:
- You will need to install the required packaged with `pip install requirements.txt` and make sure the virtual environment is activated.

# Devel:
Development notes.
## Validation Rules
Want to help out and write more rules? Great! Here's how:

I have written the rule code to make implementing new rules very easy. Yay! To add a new rule, you first need to add a method to `rules.py` to represent your rule. The method will need to match the signature `def <method_name>(logger: logging.Logger, string: str, **kwargs) -> bool`. For example:
```
def foo(x: str, logger: logging.Logger, string: str) -> bool:
        if string == x:
                return True
        return False
```

Then, to allow your rule to be used in the test framework, you will need to add it to the list of known rules returned by `rule_methods` in `rules.py`:
```
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
        "code": code,
        "foo": foo,
        "example": foo
    }
```
Note: You can add multiple aliases for your rule, but I would recommend adding the name of the method as a bare minimum.
