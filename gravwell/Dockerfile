FROM gravwell/gravwell:latest

# Dashboard JSON files are baked in so the image is self-contained.
# Provisioning (upsert via API) is handled by scripts/lab-up.sh on startup,
# which calls /api/dashboards against GRAVWELL_URL from the host.
COPY dashboards/ /opt/choochoo/dashboards/
