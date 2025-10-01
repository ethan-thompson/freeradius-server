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
