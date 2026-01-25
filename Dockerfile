FROM openjdk:11-jre-slim

# Install Z3
RUN apt-get update && apt-get install -y z3 libz3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts
COPY java/aeg-lite/target/aeg-lite-java-0.1.0-all.jar /app/bean-vulnerable-aeg.jar
COPY java/bean-vulnerable-maven-plugin/target/bean-vulnerable-maven-plugin-1.0.0.jar /app/

# Entry point
ENTRYPOINT ["java", "-jar", "/app/bean-vulnerable-aeg.jar"]
CMD ["--help"]
