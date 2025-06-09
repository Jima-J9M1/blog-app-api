# stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

# Install the C build tools needed for CGO
RUN apk add --no-cache gcc libc-dev


# Set the working directory in the container to /app
WORKDIR /app

# copy go.mod and go.sum to cache dependencies
COPY go.mod go.sum ./
# This command downloads the Go modules required by the project.
RUN go mod download

# Copy the rest of the application source code
# The following line copies the current directory (.) to the current directory in the container (.)
COPY . .

# Build the Go application
# CGO_ENABLED=0 disables CGO, making the binary static and easier to distribute
# -ldflags "-s -w" reduces binary size by stripping debug info
RUN go build -o /go-blog-api .

# stage 2: Create a minimal runtime image
FROM alpine:latest

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /go-blog-api .

# Copy the SQLite database file
# This assumes your blog.db will be generated in the root of your app when it runs locally,
# or you'll mount a volume for persistence in production.
# For simplicity, we'll copy it if it exists for local testing,
# but for production you'd use a volume or a separate DB container.
COPY --from=builder /app/blog.db ./blog.db

# Expose the port your application listens on
EXPOSE 8080

# Command to run the executable
# The default DATABASE_URL will be ./blog.db
# We'll set the PORT env var for the container
CMD ["./go-blog-api"]
