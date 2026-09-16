#!/bin/bash

docker compose -f docker-compose.noise.yml build
docker compose -f docker-compose.noise.yml up -d

sudo ./scripts/noise-scripts/replay.sh