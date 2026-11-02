# E5 (round 13): the linked anchor daemon (testbed/anchord/anchord_linked.py), built on the image every authenticated
# run used (hpr-anchord:sig, whose /app/anchord.py is byte-identical to testbed/anchord/anchord.py), so no base image is
# pulled. anchord_linked.py imports the unmodified anchord.py from its own directory and replaces only the record writer
# and the head reader. Build context: testbed/anchord.
#   docker build -f testbed/e5/anchord-linked.Dockerfile -t hpr-anchord:linked testbed/anchord
FROM hpr-anchord:sig
COPY anchord.py anchord_linked.py /app/
EXPOSE 9900
CMD ["python", "-u", "/app/anchord_linked.py"]
