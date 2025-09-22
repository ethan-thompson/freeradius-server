To use this tool, you first need to generate a docker image on your host by running `docker build -t fr-build-ubuntu22 -f scripts/docker/build/ubuntu22/Dockerfile .` from the project root.

Next, generate the compose and config files using `python3 scripts/ci/multi-server/config_parser.py scripts/ci/multi-server/example.yml.j2`.

You can then run the containers and test by running `python3 foo.py` in one window (this starts a unix server that listens for connections and echos the messages) and then `docker compose -f scripts/ci/multi-server/docker-compose.yml up freeradius`

Note:
- You will need to install the required packaged with `pip install requirements.txt` and make sure the virtual environment is activated.
