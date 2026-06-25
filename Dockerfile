FROM python:3.12-slim

# Sandboxed volunteer classifier. Outbound-only by design: the agent code only
# ever talks to the configured edge URL (see node_agent/egress.py). Run this
# container with no inbound ports published and, ideally, an egress firewall
# that allowlists only the edge host as defence-in-depth.

WORKDIR /agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY node_agent/ ./node_agent/

# Drop to a non-root user inside the sandbox.
RUN useradd --create-home --uid 10001 agent && chown -R agent /agent
USER agent

ENTRYPOINT ["python", "-m", "node_agent.cli"]
CMD ["run"]
