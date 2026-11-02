# Built with network access; RUN on the internal network with none.
# The runtime isolation is the point -- devices must not be able to reach off
# the host -- so the dependency is baked in at build time rather than fetched at
# start, which is also why the compose service cannot simply pip-install.
FROM python:3.12-slim
RUN pip install --no-cache-dir paho-mqtt==2.1.0
WORKDIR /app
COPY devices.py /app/devices.py
CMD ["python", "-u", "/app/devices.py"]
