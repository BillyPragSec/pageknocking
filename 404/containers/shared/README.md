# containers/shared/

This directory contains utility helpers that are used by the creation API container and the `mitmproxy` container.
The `Dockerfile`s for the containers copy the contents of this directory into the same directory that contains the corresponding code for each container (enabling the container code to directly import these helpers).

## Directory Structure

- `/conf` - application-specific configuration values
- `/database` - database models and interfaces used by multiple containers
- `/log` - custom JSONL (JSON-lines) loggers used to log specific events
- `/utils` - utility helpers used by multiple containers
