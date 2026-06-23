Drop your Microsensor license file here.

The compose `sensor` service expects a file at:

    sensor/license/corelight-license.txt

That file is mounted read-only at `/etc/corelight-license.txt` inside
the container. The sensor refuses to start without it.

Get the license from your Corelight account manager. The license file
itself is gitignored — it never lands in the repo.
