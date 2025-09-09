# syntax=docker/dockerfile:1.7
ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak
ARG KEYCLOAK_VERSION=24.0.5

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
ARG KEYCLOAK_VERSION

COPY provider/pom.xml ./provider/pom.xml
RUN --mount=type=cache,target=/root/.m2 \
    mvn -f provider/pom.xml -q -DskipTests -Dkeycloak.version=${KEYCLOAK_VERSION} package || true

COPY provider/ ./provider/
RUN --mount=type=cache,target=/root/.m2 \
    mvn -f provider/pom.xml -q -DskipTests -Dkeycloak.version=${KEYCLOAK_VERSION} package

FROM ${KEYCLOAK_BASE_IMAGE}:${KEYCLOAK_VERSION}

# Admin envs are fine to keep for CI/local testing; in prod you can also set at runtime.
ENV KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false \
    KEYCLOAK_ADMIN=admin \
    KEYCLOAK_ADMIN_PASSWORD=admin

USER root
COPY --from=build /src/provider/target/github-team-admin-*.jar /opt/keycloak/providers/
RUN mkdir -p /opt/keycloak/data \
 && chown -R 1000:0 /opt/keycloak \
 && chmod -R g+rw /opt/keycloak
USER 1000

# Bake Postgres + scripts at build time
RUN /opt/keycloak/bin/kc.sh build --db=postgres

# Start prebuilt server; relaxed hostname for CI
ENTRYPOINT ["/opt/keycloak/bin/kc.sh","start","--optimized","--http-enabled=true","--hostname-strict=false"]
