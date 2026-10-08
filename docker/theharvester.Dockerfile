# docker/theharvester.Dockerfile
#
# Uses the official theHarvester Docker image.
# OSINT-Lens runs the tool as an isolated container.

FROM ghcr.io/laramies/theharvester:latest

ENTRYPOINT ["theHarvester"]
