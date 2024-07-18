# mitm

The main directory that hosts our mitmproxy modules.

## Dependencies

This container is built on top of the `mitm_base` image that has all the necessary dependencies installed.

## Code
The file structure is as follows:

- `data/`
  - `admin_knock_sequence.txt` - a list of the requests of predefined page knocking sequence
  - `default_contiguous_knocks.txt` - predefined default contiguous page knocking sequences (for multiple users, use this file)
  - `knock_sequence.csv` - predefined default contiguous page knocking sequences (for multiple users, use this file)
  - `pre_authentication_urls_wordpress.txt` - pre-authentication, publicly availabel pages (these are the candidates making up the page knocking sequence requests)
- `scripts/` - contains `mitmproxy` addons that implement a new class with the `request` and `response` methods
  - `load_mitm.py` - checks environment variables and loads the corresponding, enabled modules
  - `logging_addon.py` - logs request and response data to a local file in the container
  - `knocks.py` - responsible for detecting login page requests, checks the pageknocking authentication status, and either responds with the real web application, or engages the visitor in deception.
- `Dockerfile` - the Dockerfile that builds the `mitmproxy` container
- `init-mitm.sh` - the script that loads our `mitmproxy` addons. The order in which they are loaded determines the order they execute their `request` and `repsonse` methods.

## Container Logs
You can get a shell into a container using `docker exec -it <container_name> /bin/sh`.
Various modules (e.g., knocks) have their own types of logs that are output into the file `logs/revproxy.log`.