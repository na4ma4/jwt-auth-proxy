# jwt-auth-proxy

[![CI](https://github.com/na4ma4/jwt-auth-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/na4ma4/jwt-auth-proxy/actions/workflows/ci.yml)
[![GitHub issues](https://img.shields.io/github/issues/na4ma4/jwt-auth-proxy)](https://github.com/na4ma4/jwt-auth-proxy/issues)
[![GitHub forks](https://img.shields.io/github/forks/na4ma4/jwt-auth-proxy)](https://github.com/na4ma4/jwt-auth-proxy/network)
[![GitHub stars](https://img.shields.io/github/stars/na4ma4/jwt-auth-proxy)](https://github.com/na4ma4/jwt-auth-proxy/stargazers)
[![GitHub license](https://img.shields.io/github/license/na4ma4/jwt-auth-proxy)](https://github.com/na4ma4/jwt-auth-proxy/blob/main/LICENSE)

Authentication proxy that uses JWT tokens (and supports specified legacy authentication), written entirely in Go.

## Usage

```shell
docker secret create token-ca.pem artifacts/certs/ca.pem

docker network create --driver overlay public

docker service create --name whoami \
    --network public \
    containous/whoami:latest

docker service create --name auth-proxy \
    --publish 8080:80/tcp \
    --network public \
    --env "AUDIENCE=tls-web-client-auth" \
    --env "BACKEND_URL=http://whoami/" \
    --env "REMOVE_AUTH_HEADER=true" \
    --env "PASS_HOST_HEADER=true" \
    --env 'LEGACY_USERS=bob:$2a$15$rp1JcY2nEghqsFLMolfEmuAZ92FfzANcrR0y0C6VAea7fVPnsQJC2 alice:$2a$15$xaX4rqP9lLOy/HKpCnz4y.mp2LYjzg8KYkmWwGp2/xYO2WCSHs.6i' \
    --secret "source=token-ca.pem,target=ca.pem" \
    gcr.io/na4ma4/jwt-auth-proxy:latest
```

Then browse to [http://localhost:8080/](http://localhost:8080/) to test.

Working examples:

```shell
TEST_AUTH_TOKEN="$(docker run --rm -v "$(pwd)/artifacts:/artifacts" gcr.io/na4ma4/jwt-auth-proxy:latest mktoken anne)"

curl 'http://localhost:8080/'
curl -u 'bob:builder' 'http://localhost:8080/'
curl -u 'alice:also-a-builder' 'http://localhost:8080/'
curl -u "token:${TEST_AUTH_TOKEN}" 'http://localhost:8080/'
curl -u "${TEST_AUTH_TOKEN}:" 'http://localhost:8080/'
```

Logs

```plain
$ docker service logs auth-proxy
auth-proxy.1.9v21dc2z6vlk@docker-desktop    | 10.0.0.2 - - [22/Jul/2021:05:04:27 +0000] "GET / HTTP/1.1" 401 13 "" "curl/7.64.1"
auth-proxy.1.9v21dc2z6vlk@docker-desktop    | 10.0.0.2 - bob [22/Jul/2021:05:04:27 +0000] "GET / HTTP/1.1" 200 237 "" "curl/7.64.1"
auth-proxy.1.9v21dc2z6vlk@docker-desktop    | 10.0.0.2 - alice [22/Jul/2021:05:04:29 +0000] "GET / HTTP/1.1" 200 239 "" "curl/7.64.1"
auth-proxy.1.9v21dc2z6vlk@docker-desktop    | 10.0.0.2 - anne [22/Jul/2021:05:04:32 +0000] "GET / HTTP/1.1" 200 238 "" "curl/7.64.1"
auth-proxy.1.9v21dc2z6vlk@docker-desktop    | 10.0.0.2 - anne [22/Jul/2021:05:04:32 +0000] "GET / HTTP/1.1" 200 238 "" "curl/7.64.1"
```
