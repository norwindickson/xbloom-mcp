FROM denoland/deno:2.4.5@sha256:c36ea88ae24a4e719d963b2c9de14ec22348021117fe088a437c3ba821b22b65

WORKDIR /app
COPY --chown=deno:deno app/deno.json /app/deno.json
COPY --chown=deno:deno app/index.ts /app/index.ts
RUN deno check /app/index.ts

USER deno
EXPOSE 8000
ENTRYPOINT ["deno", "run", "--allow-net", "--allow-env", "/app/index.ts"]
