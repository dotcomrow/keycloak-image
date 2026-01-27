# syntax=docker/dockerfile:1.7
ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak
ARG KEYCLOAK_VERSION
ARG KC_HTTP_RELATIVE_PATH
ARG KC_FEATURES
ARG KC_TRANSACTION_XA_ENABLED

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
ARG KC_HTTP_RELATIVE_PATH
ARG KC_FEATURES
ARG KC_TRANSACTION_XA_ENABLED

# Admin envs are fine to keep for CI/local testing; in prod you can also set at runtime.
ENV KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false \
    KEYCLOAK_ADMIN=admin \
    KEYCLOAK_ADMIN_PASSWORD=admin

USER root
COPY --from=build /src/provider/target/*.jar /opt/keycloak/providers/
COPY --from=build /src/provider/target/deps/*.jar /opt/keycloak/providers/
RUN mkdir -p /opt/keycloak/data \
 && chown -R 1000:0 /opt/keycloak \
 && chmod -R g+rw /opt/keycloak
USER 1000

# Bake Postgres + scripts at build time (build-time options must match runtime)
RUN test -n "$KC_FEATURES" \
 && test -n "$KC_HTTP_RELATIVE_PATH" \
 && test -n "$KC_TRANSACTION_XA_ENABLED" \
 && /opt/keycloak/bin/kc.sh build --db=postgres \
    --features="${KC_FEATURES}" \
    --http-relative-path="${KC_HTTP_RELATIVE_PATH}" \
    --transaction-xa-enabled="${KC_TRANSACTION_XA_ENABLED}"

# Start prebuilt server; relaxed hostname for CI
ENTRYPOINT ["/opt/keycloak/bin/kc.sh","start","--optimized","--http-enabled=true","--hostname-strict=false"]
