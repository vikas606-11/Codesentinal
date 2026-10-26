# CodeSentinal. agent — pure-Go, static, tiny image.
# Stage 1: build the static binary.
FROM golang:1.27-alpine AS build
WORKDIR /src

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

# Build.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/CodeSentinal. ./cmd/CodeSentinal.

# Stage 2: minimal runtime. distroless static = no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/CodeSentinal. /CodeSentinal.

# Read-only agent. Runs as nonroot (uid 65532) from the base image.
EXPOSE 8080
ENV LISTEN_ADDR=":8080"
ENTRYPOINT ["/CodeSentinal."]
