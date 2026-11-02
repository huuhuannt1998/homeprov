# Built with network access (apk); runs with the replica volume, the log directory and the SSH material mounted.
FROM python:3.12-alpine
RUN apk add --no-cache openssh-client
WORKDIR /app
COPY replicator.py /app/replicator.py
CMD ["python", "-u", "/app/replicator.py"]
