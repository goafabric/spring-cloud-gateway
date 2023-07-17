# run jvm multi image
docker run --pull always --name spring-cloud-gateway --rm -p8080:8080 goafabric/spring-cloud-gateway:1.0.0-SNAPSHOT

# run native image
docker run --pull always --name spring-cloud-gateway --rm -p8080:8080 goafabric/spring-cloud-gateway-native:1.0.0-SNAPSHOT -Xmx32m

# run native image arm
docker run --pull always --name spring-cloud-gateway --rm -p8080:8080 goafabric/spring-cloud-gateway-native-arm64v8:1.0.0-SNAPSHOT -Xmx32m

