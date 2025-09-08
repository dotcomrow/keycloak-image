# --- build the provider jar ---
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src

# allow CI to pass the target Keycloak version so jar compiles against same APIs
ARG KEYCLOAK_VERSION=24.0.5

COPY provider/pom.xml provider/pom.xml
RUN --mount=type=cache,target=/root/.m2 mvn -f provider/pom.xml -q -DskipTests -Dkeycloak.version=${KEYCLOAK_VERSION} package || true
COPY provider/ provider/
RUN --mount=type=cache,target=/root/.m2 mvn -f provider/pom.xml -q -DskipTests -Dkeycloak.version=${KEYCLOAK_VERSION} package

# --- Keycloak runtime with provider baked in ---
ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak
ARG KEYCLOAK_VERSION=24.0.5
FROM ${KEYCLOAK_BASE_IMAGE}:${KEYCLOAK_VERSION}

ENV KC_HEALTH_ENABLED=true     KC_METRICS_ENABLED=false     KEYCLOAK_ADMIN=admin     KEYCLOAK_ADMIN_PASSWORD=admin

USER root
COPY --from=build /src/provider/target/github-team-admin-*.jar /opt/keycloak/providers/
RUN mkdir -p /opt/keycloak/data && chown -R 1000:0 /opt/keycloak && chmod -R g+rw /opt/keycloak
USER 1000

# Build once so provider is wired in; no --auto-build at runtime
RUN /opt/keycloak/bin/kc.sh build

# default command; hostname checks relaxed for CI
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--http-enabled=true", "--hostname-strict=false"]
