FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o pipeline-watcher .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /app/pipeline-watcher /usr/local/bin/pipeline-watcher
ENTRYPOINT ["pipeline-watcher"]

