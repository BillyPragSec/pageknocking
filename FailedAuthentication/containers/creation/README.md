# Creation API

Provides a simple RESTful API, served by Flask.
Exposes the following endpoints which typically accept/return JSON:

**NOTE**: sometimes building the container may seem to hang on `apk add` steps. 
Retrying a few times will work. 
There are several issues reported with this for alpine (e.g, [#1](https://forum.gitlab.com/t/pipeline-stuck-with-fetch-https-dl-cdn-alpinelinux-org-alpine-v3-14-main-x86-64-apkindex-tar-gz/59074)).
You can also try to run docker with the args `dns-opt='options single-request'` and `net.ipv6.conf.all.disable_ipv6=1` (e.g., [#2](https://github.com/gliderlabs/docker-alpine/issues/307#issuecomment-644604465)).
