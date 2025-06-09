package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"regexp"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// --- Global Logger Instance ---
var logger *zap.Logger

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type Article struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	AuthorID  string    `json:"authorId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Session struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
}

// --- Context Key for User Info ---
type contextKey string

const contextKeyUser contextKey = "user"

// Message struct (remains the same)
type Message struct {
	Text string `json:"message"`
}

// --- Helper Functions (Updated) ---

// writeJSON sends a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("Error encoding JSON: %v", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// writeError sends a JSON error response
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// generateSessionToken generates a unique session token
func generateSessionToken() string {
	return uuid.New().String()
}

// setAuthCookie sets the session token as an HTTP-only cookie
func setAuthCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
}

// clearAuthCookie clears the session cookie
func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		Path:     "/",
	})
}

// --- Middleware Functions (Updated) ---

// loggingMiddleware logs details of each incoming request
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("Request handled",
		zap.String("method", r.Method),
	    zap.String("path", r.URL.Path),
	    zap.String("remote_addr", r.RemoteAddr),
	    zap.Duration("duration", time.Since(start)),
	)
	})
}

// authMiddleware checks for a valid session and adds user info to context
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Missing authentication token. Please log in.")
			return
		}

		sessionToken := cookie.Value

		session, err := GetSessionByToken(sessionToken) // Use DB function
		if err != nil || session.ExpiresAt.Before(time.Now()) {
			if err == nil && session.ExpiresAt.Before(time.Now()) {
				// Clean up expired session from DB
				DeleteSessionByToken(sessionToken) // Use DB function
				logger.Info("Expired session cleaned up", zap.String("session_token", sessionToken))
			}
			clearAuthCookie(w)
			writeError(w, http.StatusUnauthorized, "Session expired or invalid. Please log in again.")
			logger.Info("Authentication failed: Session invalid or expired",
		               zap.String("session_token", sessionToken),
					   zap.Error(err),
		)
			return
		}

		user, err := GetUserByID(session.UserID) // Use DB function
		if err != nil {
			writeError(w, http.StatusInternalServerError, "User associated with session not found. Please contact support.")
			logger.Fatal("CRITICAL: Session token points to non-existent user",
				zap.String("session_token", sessionToken),
				zap.String("user_id", session.UserID),
				zap.Error(err),
			)
			clearAuthCookie(w)
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyUser, user)
		r = r.WithContext(ctx)
		logger.Info("Auth handled",
	    zap.String("session_token", sessionToken),
	    zap.String("session_user", session.UserID),
	    zap.String("session_expires", session.ExpiresAt.String()),
	)
		
		next.ServeHTTP(w, r)
	})
}

// getUserFromContext retrieves the user from the request context
func getUserFromContext(r *http.Request) (User, bool) {
	user, ok := r.Context().Value(contextKeyUser).(User)
	return user, ok
}

// validation Helper Function

// isValid User name checks if a username meets critera

func isValidUsername(username string) string {
	if len(username) < 3 || len(username) > 20 {
		return "Username must be between 3 and 20 characters long."
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) {
		return "Username can only contain letters, numbers, and underscores."
	}

	return ""
}

// isValidPassword checks if a password meets criteria
func isValidPassword(password string) string {
	if len(password) < 8 {
		return "Password must be at least 8 characters long."
	}
	// Basic complexity check: require at least one uppercase, one lowercase, one digit, one special character
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return "Password must contain at least one uppercase letter."
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return "Password must contain at least one lowercase letter."
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return "Password must contain at least one digit."
	}
	if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]`).MatchString(password) {
		return "Password must contain at least one special character."
	}
	return ""
}

// isValidTitle checks if an article title meets criteria
func isValidTitle(title string) string {
	if len(title) < 5 || len(title) > 100 {
		return "Article title must be between 5 and 100 characters long."
	}
	return ""
}

// isValidContent checks if article content meets criteria
func isValidContent(content string) string {
	if len(content) < 10 {
		return "Article content must be at least 10 characters long."
	}
	// Optional: Max length for content
	if len(content) > 5000 {
		return "Article content cannot exceed 5000 characters."
	}
	return ""
}

// --- API Handlers (Updated to use DB functions) ---

// registerUser handles user registration
// --- API Handlers (Updated to use logger) ---
func registerUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		logger.Warn("Failed to decode register user request body", zap.Error(err))
		return
	}

	if errMsg := isValidUsername(newUser.Username); errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		logger.Warn("Invalid username during registration", zap.String("username", newUser.Username), zap.String("error_message", errMsg))
		return
	}

	if errMsg := isValidPassword(newUser.Password); errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		logger.Warn("Invalid password during registration", zap.String("username", newUser.Username), zap.String("error_message", errMsg))
		return
	}

	_, err = GetUserByUsername(newUser.Username)
	if err == nil {
		writeError(w, http.StatusConflict, "Username already exists")
		logger.Info("Registration failed: Username already exists", zap.String("username", newUser.Username))
		return
	}
	// if err != nil && err != sql.ErrNoRows {
	// 	writeError(w, http.StatusInternalServerError, "Database error checking username availability")
	// 	logger.Error("DB Error checking username availability", zap.Error(err), zap.String("username", newUser.Username))
	// 	return
	// }

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password. Please try again.")
		logger.Error("Error hashing password", zap.Error(err))
		return
	}

	newUser.ID = uuid.New().String()
	newUser.Password = string(hashedPassword)

	err = InsertUser(newUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to register user. Please try again.")
		logger.Error("DB Error inserting user", zap.Error(err), zap.String("username", newUser.Username))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "User registered successfully", "id": newUser.ID})
	logger.Info("New user registered", zap.String("username", newUser.Username), zap.String("user_id", newUser.ID))
}

// loginUser handles user login
func loginUser(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		logger.Warn("Failed to decode login request body", zap.Error(err))
		return
	}

	if credentials.Username == "" || credentials.Password == "" {
		writeError(w, http.StatusBadRequest, "Username and password are required")
		logger.Warn("Login failed: Missing username or password in request")
		return
	}

	foundUser, err := GetUserByUsername(credentials.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusUnauthorized, "Invalid username or password")
			logger.Info("Login failed: User not found", zap.String("username", credentials.Username))
		} else {
			writeError(w, http.StatusInternalServerError, "Database error during login")
			logger.Error("DB Error getting user by username during login", zap.Error(err), zap.String("username", credentials.Username))
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(credentials.Password))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		logger.Info("Login failed: Invalid password", zap.String("username", credentials.Username))
		return
	}

	sessionToken := generateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)

	newSession := Session{
		Token:  sessionToken,
		UserID:    foundUser.ID,
		ExpiresAt: expiresAt,
	}

	err = InsertSession(newSession)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create session.")
		logger.Error("DB Error inserting session", zap.Error(err), zap.String("user_id", foundUser.ID))
		return
	}

	setAuthCookie(w, sessionToken)

	writeJSON(w, http.StatusOK, map[string]string{"message": "Login successful", "userId": foundUser.ID})
	logger.Info("User logged in successfully", zap.String("username", foundUser.Username), zap.String("user_id", foundUser.ID))
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": "Already logged out or no active session"})
		logger.Info("Logout request but no session cookie found", zap.Error(err))
		return
	}

	sessionToken := cookie.Value

	err = DeleteSessionByToken(sessionToken)
	if err != nil {
		logger.Error("Error deleting session token from DB during logout", zap.String("session_token", sessionToken), zap.Error(err))
	}

	clearAuthCookie(w)

	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
	logger.Info("User logged out", zap.String("session_token", sessionToken))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Authenticated user not found in context.")
		logger.Fatal("CRITICAL: User not found in context for protected handler. Middleware failed?")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("Welcome, %s! You accessed a protected resource.", user.Username)})
	logger.Info("Protected resource accessed", zap.String("user_id", user.ID), zap.String("username", user.Username))
}

func getArticles(w http.ResponseWriter, r *http.Request) {
	articlesList, err := GetArticles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve articles.")
		logger.Error("DB Error getting articles", zap.Error(err))
		return
	}

	writeJSON(w, http.StatusOK, articlesList)
	logger.Info("Retrieved all articles")
}

func getArticleByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	articleID := vars["id"]

	article, err := GetArticleByID(articleID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "Article not found")
			logger.Info("Article not found", zap.String("article_id", articleID))
		} else {
			writeError(w, http.StatusInternalServerError, "Database error retrieving article")
			logger.Error("DB Error getting article by ID", zap.String("article_id", articleID), zap.Error(err))
		}
		return
	}

	writeJSON(w, http.StatusOK, article)
	logger.Info("Retrieved article by ID", zap.String("article_id", articleID), zap.String("title", article.Title))
}

func createArticle(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Authenticated user not found in context.")
		logger.Fatal("CRITICAL: User not found in context for createArticle. Middleware failed?")
		return
	}

	var newArticle Article
	err := json.NewDecoder(r.Body).Decode(&newArticle)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		logger.Warn("Failed to decode create article request body", zap.Error(err))
		return
	}

	if errMsg := isValidTitle(newArticle.Title); errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		logger.Warn("Invalid article title for creation", zap.String("title", newArticle.Title), zap.String("error_message", errMsg))
		return
	}
	if errMsg := isValidContent(newArticle.Content); errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		logger.Warn("Invalid article content for creation", zap.String("title", newArticle.Title), zap.String("error_message", errMsg))
		return
	}

	newArticle.ID = uuid.New().String()
	newArticle.AuthorID = user.ID
	newArticle.CreatedAt = time.Now()
	newArticle.UpdatedAt = time.Now()

	err = InsertArticle(newArticle)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create article.")
		logger.Error("DB Error inserting article", zap.Error(err), zap.String("title", newArticle.Title), zap.String("author_id", user.ID))
		return
	}

	writeJSON(w, http.StatusCreated, newArticle)
	logger.Info("Article created",
		zap.String("article_id", newArticle.ID),
		zap.String("title", newArticle.Title),
		zap.String("author_id", user.ID),
		zap.String("author_username", user.Username),
	)
}

func updateArticle(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Authenticated user not found in context.")
		logger.Fatal("CRITICAL: User not found in context for updateArticle. Middleware failed?")
		return
	}

	vars := mux.Vars(r)
	articleID := vars["id"]

	existingArticle, err := GetArticleByID(articleID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "Article not found")
			logger.Info("Article not found for update", zap.String("article_id", articleID))
		} else {
			writeError(w, http.StatusInternalServerError, "Database error retrieving article for update")
			logger.Error("DB Error getting article for update", zap.String("article_id", articleID), zap.Error(err))
		}
		return
	}

	if existingArticle.AuthorID != user.ID {
		writeError(w, http.StatusForbidden, "You are not authorized to update this article")
		logger.Warn("Unauthorized attempt to update article",
			zap.String("article_id", articleID),
			zap.String("attempted_by_user_id", user.ID),
			zap.String("actual_author_id", existingArticle.AuthorID),
		)
		return
	}

	var updatedData struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	err = json.NewDecoder(r.Body).Decode(&updatedData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		logger.Warn("Failed to decode update article request body", zap.Error(err), zap.String("article_id", articleID))
		return
	}

	if updatedData.Title != "" {
		if errMsg := isValidTitle(updatedData.Title); errMsg != "" {
			writeError(w, http.StatusBadRequest, errMsg)
			logger.Warn("Invalid updated article title", zap.String("article_id", articleID), zap.String("title", updatedData.Title), zap.String("error_message", errMsg))
			return
		}
		existingArticle.Title = updatedData.Title
	}
	if updatedData.Content != "" {
		if errMsg := isValidContent(updatedData.Content); errMsg != "" {
			writeError(w, http.StatusBadRequest, errMsg)
			logger.Warn("Invalid updated article content", zap.String("article_id", articleID), zap.String("error_message", errMsg))
			return
		}
		existingArticle.Content = updatedData.Content
	}
	existingArticle.UpdatedAt = time.Now()

	err = UpdateArticle(existingArticle)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update article.")
		logger.Error("DB Error updating article", zap.Error(err), zap.String("article_id", existingArticle.ID))
		return
	}

	writeJSON(w, http.StatusOK, existingArticle)
	logger.Info("Article updated",
		zap.String("article_id", existingArticle.ID),
		zap.String("title", existingArticle.Title),
		zap.String("author_id", user.ID),
	)
}

func deleteArticle(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Authenticated user not found in context.")
		logger.Fatal("CRITICAL: User not found in context for deleteArticle. Middleware failed?")
		return
	}

	vars := mux.Vars(r)
	articleID := vars["id"]

	existingArticle, err := GetArticleByID(articleID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "Article not found")
			logger.Info("Article not found for deletion", zap.String("article_id", articleID))
		} else {
			writeError(w, http.StatusInternalServerError, "Database error retrieving article for delete")
			logger.Error("DB Error getting article for delete", zap.String("article_id", articleID), zap.Error(err))
		}
		return
	}

	if existingArticle.AuthorID != user.ID {
		writeError(w, http.StatusForbidden, "You are not authorized to delete this article")
		logger.Warn("Unauthorized attempt to delete article",
			zap.String("article_id", articleID),
			zap.String("attempted_by_user_id", user.ID),
			zap.String("actual_author_id", existingArticle.AuthorID),
		)
		return
	}

	err = DeleteArticle(articleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete article.")
		logger.Error("DB Error deleting article", zap.Error(err), zap.String("article_id", articleID))
		return
	}

	writeJSON(w, http.StatusNoContent, nil)
	logger.Info("Article deleted",
		zap.String("article_id", articleID),
		zap.String("title", existingArticle.Title),
		zap.String("deleted_by_user_id", user.ID),
	)
}

// --- Main Application Logic (Updated for Zap) ---

func main() {
	// Initialize Zap logger (development configuration)
	// For production, use zap.NewProduction()
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := logger.Sync(); err != nil { // Ensure all buffered logs are written
			fmt.Printf("Failed to sync logger: %v\n", err)
		}
	}()

	// Load configuration
	cfg := LoadConfig()

	// Initialize database using config
	InitDB(cfg.DatabaseURL)
	defer CloseDB()

	r := mux.NewRouter()

	r.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Message{Text: "Hello from Go API!"})
	}).Methods("GET")
	r.HandleFunc("/api/register", registerUser).Methods("POST")
	r.HandleFunc("/api/login", loginUser).Methods("POST")
	r.HandleFunc("/api/logout", logoutUser).Methods("POST")

	r.Handle("/api/protected", authMiddleware(http.HandlerFunc(protectedHandler))).Methods("GET")

	// Article Endpoints
	r.HandleFunc("/api/articles", getArticles).Methods("GET")
	r.HandleFunc("/api/articles/{id}", getArticleByID).Methods("GET")

	r.Handle("/api/articles", authMiddleware(http.HandlerFunc(createArticle))).Methods("POST")
	r.Handle("/api/articles/{id}", authMiddleware(http.HandlerFunc(updateArticle))).Methods("PUT")
	r.Handle("/api/articles/{id}", authMiddleware(http.HandlerFunc(deleteArticle))).Methods("DELETE")

	loggedRouter := loggingMiddleware(r)

	logger.Info("API Server starting", zap.String("port", cfg.Port))
	err = http.ListenAndServe(":"+cfg.Port, loggedRouter)
	if err != nil {
		logger.Fatal("Server failed to start", zap.Error(err))
	}
}

