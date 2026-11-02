# E8 (round 13): the anchor image of the E8 run. The repository's hardened daemon (testbed/anchord/anchord.py: threaded
# serving, read limits, operator key for markers, tagged replies) run through the linked entry point
# (testbed/anchord/anchord_linked.py: hash-linked records, head pushes that extend the witness's last head), on the
# same base image as testbed/anchord/Dockerfile (python:3.12-slim, standard library only, no pull at run time).
# Build context: testbed/anchord. Built by testbed/e8/run_e8.sh under the tag hpr-anchord:e8 only; never by
# `docker compose build` in testbed/real, which would re-tag the default deployment's hpr-anchord:1.
#   docker build -f testbed/e8/anchord-e8.Dockerfile -t hpr-anchord:e8 testbed/anchord
FROM python:3.12-slim
WORKDIR /app
COPY anchord.py anchord_linked.py /app/
EXPOSE 9900
CMD ["python", "-u", "/app/anchord_linked.py"]
