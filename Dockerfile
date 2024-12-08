FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
