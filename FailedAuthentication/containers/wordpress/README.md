# containers/wordpress/

Contains necessary configurations and files for `docker-compose` to bring up all containers necessary to proxy an instance of WordPress.

Make sure to change the values in `.env` and `docker-compose.yml` to reflect your setup. In particular, make sure to:
- change `PROXY_ADDRESS` in `.env` to be the address which hosts the WordPress container
- change the `*_PORT` values in `.env` to be the public-facing ports of the host machine.
  - `PROXY_PORT` exposes access to the web application *through the proxy* (this is the port you should be using)
  - `HTTP_PORT` exposes *direct* access the web application over HTTP (e.g., WordPress)
  - `HTTPS_PORT` exposes *direct* access the web application over HTTPS (add a mapping for `HTTPS_PORT` to 443 for the container)
  - `PHPMYADMIN_PORT` exposes an instance of PHPMyAdmin that is connected to the database used by the proxy
  - `CREATIONAPI_PORT` exposes the simple creation API. The IP address and port here will need to be set as the `Creation Domain` option in the extension UI.
- change the images for `honeypot_webapp` and `honeypot_db` in `docker-compose.yml`. If you would prefer, you can email us to request the images we used for development.

Run `docker-compose up -d` in this directory to bring up all containers in the background.

## Notes
- the default images used by `honeypot_webapp` and `honeypot_webapp_db` are the ones we used for development. You can login to the admin panel of WordPress at `/wp-admin/` with the credentials `admin/spoof_password_to_change`. Feel free to change the images used.