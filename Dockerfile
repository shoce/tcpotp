
# https://hub.docker.com/_/golang/tags
FROM golang:1.23.4-alpine3.20 AS build
RUN mkdir -p /root/tcpotp/
COPY tcpotp.go go.mod /root/tcpotp/
RUN go version
RUN go build -o /root/tcpotp/tcpotp /root/tcpotp/tcpotp.go
RUN ls -l -a /root/tcpotp/


# https://hub.docker.com/_/alpine/tags
FROM alpine:3.20.3
RUN apk add --no-cache gcompat && ln -s -f -v ld-linux-x86-64.so.2 /lib/libresolv.so.2
RUN mkdir -p /opt/tcpotp/
COPY --from=build /root/tcpotp/tcpotp /bin/tcpotp
WORKDIR /opt/tcpotp/
ENTRYPOINT ["/bin/tcpotp"]


