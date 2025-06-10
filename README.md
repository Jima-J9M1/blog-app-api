-----

# Go Blog API

A simple, yet robust, RESTful API for a blog application built with Go, featuring user authentication, article management (CRUD), and best practices like structured logging, input validation, and containerization.

-----

## Table of Contents

  * [Features](#features)
  * [Technologies Used](https://www.google.com/search?q=%23technologies-used)
  * [Getting Started](https://www.google.com/search?q=%23getting-started)
      * [Prerequisites](https://www.google.com/search?q=%23prerequisites)
      * [Clone the Repository](https://www.google.com/search?q=%23clone-the-repository)
      * [Run Locally](https://www.google.com/search?q=%23run-locally)
      * [Run with Docker](https://www.google.com/search?q=%23run-with-docker)
      * [Run Tests](https://www.google.com/search?q=%23run-tests)
  * [API Endpoints](https://www.google.com/search?q=%23api-endpoints)
      * [Authentication](https://www.google.com/search?q=%23authentication)
      * [Articles](https://www.google.com/search?q=%23articles)
  * [Database](https://www.google.com/search?q=%23database)
  * [Configuration](https://www.google.com/search?q=%23configuration)
  * [Logging](https://www.google.com/search?q=%23logging)
  * [Future Enhancements](https://www.google.com/search?q=%23future-enhancements)
  * [License](https://www.google.com/search?q=%23license)

-----

## Features

This project demonstrates building a Go API with the following key features:

  * **RESTful API:** Standard HTTP methods (GET, POST, PUT, DELETE) for resource interaction.
  * **User Authentication:**
      * User registration with secure password hashing (bcrypt).
      * User login using session-based authentication (HTTP-only cookies).
      * Session persistence backed by SQLite.
      * Logout functionality.
  * **Article Management (CRUD):**
      * Create, Read (all/single), Update, and Delete blog articles.
      * Authorization checks to ensure users can only modify/delete their own articles.
  * **Middleware:**
      * Request logging middleware for monitoring.
      * Authentication middleware to protect routes.
  * **Input Validation:** Robust server-side validation for user input (e.g., username/password complexity, article content length) using regular expressions.
  * **Database Integration:** Persistent data storage using **SQLite** (`github.com/mattn/go-sqlite3`).
  * **Advanced Routing:** Utilizes **Gorilla Mux** for clean and expressive routing, including path parameters and method matching.
  * **Structured Logging:** Implements **`go.uber.org/zap`** for high-performance, structured (JSON) logging, improving observability.
  * **Configuration Management:** Loads application settings (port, database URL) from environment variables, with sensible defaults.
  * **Testing:** Basic unit/integration tests for handlers, using an in-memory SQLite database for isolation.
  * **Containerization:** **`Dockerfile`** for packaging the application into a lightweight Docker image for consistent deployment.

-----

## Technologies Used

  * **Go (Golang)**
  * **`net/http`**: Go's standard library for building HTTP servers.
  * **`github.com/gorilla/mux`**: HTTP router.
  * **`github.com/mattn/go-sqlite3`**: SQLite database driver.
  * **`golang.org/x/crypto/bcrypt`**: Password hashing.
  * **`github.com/google/uuid`**: UUID generation.
  * **`go.uber.org/zap`**: Structured logging.
  * **Docker**: Containerization platform.

-----

## Getting Started

Follow these steps to set up and run the project on your local machine.

### Prerequisites

Before you begin, ensure you have the following installed:

  * **Go**: Version 1.22 or higher. [Download and install Go](https://golang.org/doc/install)
  * **Docker Desktop**: If you plan to run with Docker. [Download and install Docker](https://www.docker.com/products/docker-desktop)
  * **`curl`** or a tool like Postman for API testing.

### Clone the Repository

```bash
git clone <repository_url> # Replace with your actual repository URL
cd go-blog-api
```

### Run Locally

1.  **Install Dependencies:**

    ```bash
    go mod tidy
    ```

2.  **Build the Application:**

    ```bash
    go build -o go-blog-api .
    ```

    This creates an executable named `go-blog-api` in your project root.

3.  **Run the Application:**
    You can specify environment variables, or it will use defaults (`PORT=8080`, `DATABASE_URL=./blog.db`).

      * **Using default settings:**
        ```bash
        ./go-blog-api
        ```
      * **Using custom settings (Linux/macOS):**
        ```bash
        export PORT=9000
        export DATABASE_URL="./my_custom_blog.db"
        ./go-blog-api
        ```
      * **Using custom settings (Windows Command Prompt):**
        ```cmd
        set PORT=9000
        set DATABASE_URL=.\my_custom_blog.db
        go-blog-api.exe
        ```
      * **Using custom settings (Windows PowerShell):**
        ```powershell
        $env:PORT="9000"
        $env:DATABASE_URL="./my_custom_blog.db"
        .\go-blog-api.exe
        ```

    The API will start listening on the specified port. By default, it creates an SQLite database file named `blog.db` in the project root.

-----

### Run with Docker

1.  **Build the Docker Image:**
    Navigate to the project root where your `Dockerfile` is located.

    ```bash
    docker build -t go-blog-api .
    ```

2.  **Run the Docker Container:**
    This maps port 8080 from your host to port 8080 inside the container.

    ```bash
    docker run -p 8080:8080 --name blog-app go-blog-api
    ```

    You can also pass environment variables to the container:

    ```bash
    docker run -p 9000:8080 -e PORT=8080 -e DATABASE_URL=/app/blog.db --name blog-app go-blog-api
    ```

    *(Note: The container is running on port 8080 internally, so we use `-e PORT=8080` even if you map host port 9000 to it.)*

-----

### Run Tests

To run all automated tests for the project:

```bash
go test -v
```

*(The `-v` flag provides verbose output for each test case.)*

-----

## API Endpoints

All endpoints respond with `application/json` content type. Errors are returned with appropriate HTTP status codes and a JSON object like `{"error": "Error message"}`.

### Authentication

| Method | Path           | Description                         | Request Body (JSON)                                       | Response (JSON)                                           |
| :----- | :------------- | :---------------------------------- | :-------------------------------------------------------- | :-------------------------------------------------------- |
| `POST` | `/api/register` | Register a new user                 | `{"username": "string", "password": "string"}`            | `{"message": "User registered successfully", "id": "uuid"}` (`201 Created`) |
| `POST` | `/api/login`   | Authenticate and get a session cookie | `{"username": "string", "password": "string"}`            | `{"message": "Login successful", "userId": "uuid"}` (`200 OK`) + `Set-Cookie: session_token=...` |
| `POST` | `/api/logout`  | Invalidate current user session     | `(None)`                                                  | `{"message": "Logged out successfully"}` (`200 OK`)     |
| `GET`  | `/api/protected`| Protected test endpoint            | `(None)`                                                  | `{"message": "Welcome, <username>!..."}` (`200 OK`)     |

### Articles

| Method | Path                | Description                        | Request Body (JSON)                                             | Auth Required | Response (JSON)                                    |
| :----- | :------------------ | :--------------------------------- | :-------------------------------------------------------------- | :------------ | :------------------------------------------------- |
| `GET`  | `/api/articles`     | Get all articles                   | `(None)`                                                        | No            | `[ArticleObject, ...]` (`200 OK`)                  |
| `GET`  | `/api/articles/{id}`| Get a single article by ID         | `(None)`                                                        | No            | `ArticleObject` (`200 OK`)                         |
| `POST` | `/api/articles`     | Create a new article               | `{"title": "string", "content": "string"}`                    | Yes           | `CreatedArticleObject` (`201 Created`)             |
| `PUT`  | `/api/articles/{id}`| Update an existing article         | `{"title": "string", "content": "string"}` (partial updates) | Yes           | `UpdatedArticleObject` (`200 OK`)                  |
| `DELETE`|`/api/articles/{id}`| Delete an article                  | `(None)`                                                        | Yes           | `(No Content)` (`204 No Content`)                  |

**`ArticleObject` Structure:**

```json
{
  "id": "string (uuid)",
  "title": "string",
  "content": "string",
  "authorId": "string (uuid)",
  "createdAt": "datetime (ISO 8601)",
  "updatedAt": "datetime (ISO 8601)"
}
```

-----

## Database

The application uses a **SQLite** database. By default, it creates `blog.db` in the application's working directory.

  * **Tables:** `users`, `articles`, `sessions`.
  * **Foreign Key Constraints:** `articles.author_id` and `sessions.user_id` reference `users.id` with `ON DELETE CASCADE`.

-----

## Configuration

The application uses **environment variables** for configuration. Defaults are provided if variables are not set.

  * `PORT`: The port on which the server will listen (default: `8080`).
  * `DATABASE_URL`: The path to the SQLite database file (default: `./blog.db`). For Docker, it's usually `/app/blog.db`.

-----

## Logging

The API utilizes **`go.uber.org/zap`** for structured logging.

  * **Development Mode:** By default, logs are human-readable (colored console output).
  * **Production Mode:** If you change `zap.NewDevelopment()` to `zap.NewProduction()` in `main.go`, logs will be emitted in JSON format, ideal for log aggregation systems.

-----

## Future Enhancements

  * **Database Migrations:** Implement a database migration tool (e.g., `golang-migrate`) for schema evolution.
  * **More Advanced Validation:** Integrate a dedicated validation library for more complex rules.
  * **Refresh Tokens:** Implement refresh tokens for better session management and security.
  * **Error Handling Refinements:** Introduce custom error types for more granular error reporting.
  * **Testing Coverage:** Expand test coverage for all functions and edge cases.
  * **Docker Compose:** Set up `docker-compose.yml` to run the API alongside a separate database container (e.g., PostgreSQL).
  * **HTTPS/TLS:** Add HTTPS support for secure communication in production.
  * **Deployment CI/CD:** Set up a Continuous Integration/Continuous Development pipeline.

-----

## License

This project is open-source and available under the [MIT License](https://www.google.com/search?q=LICENSE). *(Note: You might need to create a `LICENSE` file in your repository with the MIT License text if you choose this.)*
