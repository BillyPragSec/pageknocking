# Knocking on Admin’s Door: Protecting Critical Web Applications with Deception 

This repository includes the artifacts from the DIMVA 2024 paper entitled "Knocking on Admin’s Door: Protecting Critical Web Applications with Deception" by Billy Tsouvalas and Nick Nikiforakis.

Details on functionality and implementation of the supplementary authentication mechanism, PageKnocker, are included in the aforementioned paper. In this repository, we provide the code to replicate the deployment configuration used for out work.

As outlined in the paper, our implementation relies on three main components:
- Containerization (docker)
- Server-side request manipulation (mitmproxy)
- Reverse Proxy (nginx)

We note that this work functions as a continuation of the prior work carried out by the PragSec lab - '[Click This, Not That: Extending Web Authentication with Deception](https://github.com/BillyPragSec/parallax)'

## Directory Structure:
- 404
  - `containers/`
    - `creation/` - API for web application management
    - `mitm/` - `mitmproxy` proxy scripts for pageknock management and response manipulation (404)
    - `mitm_base/` - the base image for `mitmproxy` with dependencies (should only need to be built once)
    - `shared/` - code used by both the containers for `creation/` and `mitm/` (e.g., database modeling, utilities, etc.)
    - `wordpress/` - example app that can be deployed with `docker-compose`
- FailedAuthentication
  - `containers/`
    - `creation/` - API for web application management
    - `mitm/` - `mitmproxy` proxy scripts for pageknock management and response manipulation (fake login page)
    - `mitm_base/` - the base image for `mitmproxy` with dependencies (should only need to be built once)
    - `shared/` - code used by both the containers for `creation/` and `mitm/` (e.g., database modeling, utilities, etc.)
    - `wordpress/` - example app that can be deployed with `docker-compose`
