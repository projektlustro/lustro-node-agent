# syntax=docker/dockerfile:1

# Sandboxed volunteer classifier. Outbound-only by design: the agent code only
# ever talks to the configured edge URL (see node_agent/egress.py). Run this
# container with no inbound ports published and, ideally, an egress firewall
# that allowlists only the edge host as defence-in-depth.

FROM dhi.io/python:3.13-dev AS build
WORKDIR /agent
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/agent/deps -r requirements.txt
# The release is self-contained: ship the verified classifier bundle and
# pre-warm the multilingual E5 ONNX weights during the image build. Runtime
# inference is local-only and cannot fetch executable model material.
COPY model/ /agent/model/
RUN mkdir -p /agent/embed-cache \
    && PYTHONPATH=/agent/deps python -c \
      "from fastembed import TextEmbedding; TextEmbedding(model_name='intfloat/multilingual-e5-large', cache_dir='/agent/embed-cache')" \
    && chmod -R a+rwX /agent/embed-cache

FROM dhi.io/python:3.13
WORKDIR /agent
ENV PYTHONPATH=/agent/deps
# Fixed, writable HOME so Path.home() (node_agent/keys.py, cli.py) resolves
# to a known, host-mountable path regardless of what /etc/passwd the DHI
# runtime image ships for its default non-root user.
ENV HOME=/agent
# Production pinned core public key (raw Ed25519, base64). Public, not secret.
# CI can override via --build-arg; volunteers can still override at runtime.
ARG PINNED_KEY_B64=Zb4MWkGcrXN7U/V19Vi7wIHwzPlgqENKuypGr0WoW90=
ENV LUSTRO_NODE_AGENT_PINNED_KEY_B64=${PINNED_KEY_B64}
ENV LUSTRO_NODE_MODEL_ROOT=/agent/model
ENV LUSTRO_NODE_EMBED_CACHE=/agent/embed-cache
COPY --from=build /agent/deps /agent/deps
COPY --from=build /agent/model /agent/model
COPY --from=build /agent/embed-cache /agent/embed-cache
COPY node_agent/ ./node_agent/

# DHI runtime images already run as a non-root user by default — no USER
# directive needed.
ENTRYPOINT ["python", "-m", "node_agent.cli"]
CMD ["run"]
