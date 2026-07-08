# syntax=docker/dockerfile:1

# Sandboxed volunteer classifier. Outbound-only by design: the agent code only
# ever talks to the configured edge URL (see node_agent/egress.py). Run this
# container with no inbound ports published and, ideally, an egress firewall
# that allowlists only the edge host as defence-in-depth.

FROM dhi.io/python:3.13-dev AS build
WORKDIR /agent
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/agent/deps -r requirements.txt

FROM dhi.io/python:3.13
WORKDIR /agent
ENV PYTHONPATH=/agent/deps
# Fixed, writable HOME so Path.home() (node_agent/keys.py, cli.py) resolves
# to a known, host-mountable path regardless of what /etc/passwd the DHI
# runtime image ships for its default non-root user.
ENV HOME=/agent
COPY --from=build /agent/deps /agent/deps
COPY node_agent/ ./node_agent/

# DHI runtime images already run as a non-root user by default — no USER
# directive needed.
ENTRYPOINT ["python", "-m", "node_agent.cli"]
CMD ["run"]
