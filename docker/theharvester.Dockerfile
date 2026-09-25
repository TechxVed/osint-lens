# docker/theharvester.Dockerfile
#
# Builds an isolated environment for theHarvester so its dependencies
# never conflict with this project's own Python virtual environment.
#
# Build with (from the project root):
#   docker build -t osint-lens-theharvester -f docker/theharvester.Dockerfile .
#
# NOT built or tested in the sandbox this project was authored in (no
# Docker daemon / no registry access there). Build and test this on your
# own Kali machine before your demo -- see README "Testing this plugin
# on Kali Linux".

FROM python:3.11-slim

# theHarvester needs git to install from source, and a couple of
# standard build tools some of its dependencies compile against.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester
WORKDIR /opt/theHarvester
RUN pip install --no-cache-dir -r requirements/base.txt

# /output is where we bind-mount the host's temp directory so the JSON
# result file theHarvester writes inside the container becomes visible
# on the host after the container exits.
RUN mkdir /output

ENTRYPOINT ["python3", "theHarvester.py"]
