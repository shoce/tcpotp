
# https://hub.docker.com/_/golang/tags
FROM golang:1.25-alpine AS build
RUN mkdir -p /tcpotp/
COPY tcpotp.go go.mod /tcpotp/
RUN go version
RUN go build -o /tcpotp/tcpotp /tcpotp/tcpotp.go
RUN ls -l -a /tcpotp/


# https://hub.docker.com/_/alpine/tags
FROM alpine:3
RUN apk add --no-cache gcompat && ln -s -f -v ld-linux-x86-64.so.2 /lib/libresolv.so.2
RUN mkdir -p /opt/tcpotp/
WORKDIR /opt/tcpotp/
COPY --from=build /tcpotp/tcpotp /bin/tcpotp
ENTRYPOINT ["/bin/tcpotp"]


