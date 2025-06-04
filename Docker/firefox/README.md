Run these commands from this directory.

# Build the docker image

```
docker build -t wolfpkcs11-firefox-test .
```

# Run the Firefox tests

```
docker run --rm \
	-v ./test-files:/test-files:ro \
	wolfpkcs11-firefox-test \
	bash /test-files/selenium-script.sh
```
