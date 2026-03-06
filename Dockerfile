FROM --platform=linux/amd64 maven:3.9.6-eclipse-temurin-21 AS build

WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -X

FROM --platform=linux/amd64 eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/*jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]