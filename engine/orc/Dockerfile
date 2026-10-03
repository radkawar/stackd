# Build explicitly: docker build -t stackd/orc:2.2.2 engine/orc
# Only this build resolves Maven artifacts. The Go adapter never pulls images.
FROM maven:3.9.12-eclipse-temurin-17@sha256:a0603aab698040d9c94259f379ec0487da1678560748d6c7508483034033c53d AS dependencies
RUN mvn --batch-mode --strict-checksums org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy \
    -Dartifact=org.apache.orc:orc-tools:2.2.2:jar:uber \
    -DoutputDirectory=/opt/orc
COPY InventoryEncoder.java /tmp/InventoryEncoder.java
RUN javac -cp /opt/orc/orc-tools-2.2.2-uber.jar -d /opt/orc /tmp/InventoryEncoder.java

FROM eclipse-temurin:17.0.18_8-jre-jammy@sha256:642d45bf22d3cb9face159181732ed9fa70873b2681e50445eff7d4785c176bb
COPY --from=dependencies /opt/orc/ /opt/orc/
RUN mkdir /work && chown 65534:65534 /work
USER 65534:65534
WORKDIR /work
ENV TZ=UTC
ENTRYPOINT ["java", "-Xmx256m", "-Duser.timezone=UTC", "-Djava.io.tmpdir=/work", "-cp", "/opt/orc:/opt/orc/*", "InventoryEncoder"]
