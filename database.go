package main

import (
	"database/sql"
	"fmt"
	// "log" // Remove standard log import
	"time"

	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver
	"go.uber.org/zap"               // New: Import Zap
)

var DB *sql.DB // Global database connection

func InitDB(dataSourceName string) {
	var err error
	DB, err = sql.Open("sqlite3", dataSourceName)
	if err != nil {
		// Using Zap's Fatal which exits the application
		logger.Fatal("Failed to open database", zap.Error(err), zap.String("db_path", dataSourceName))
	}

	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(5)
	DB.SetConnMaxLifetime(5 * time.Minute)

	if err = DB.Ping(); err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err), zap.String("db_path", dataSourceName))
	}

	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS articles (
		id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		content TEXT NOT NULL,
		author_id TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);
	`

	_, err = DB.Exec(createTablesSQL)
	if err != nil {
		logger.Fatal("Failed to create tables", zap.Error(err))
	}

	logger.Info("Database initialized successfully", zap.String("db_path", dataSourceName))
}

// CloseDB closes the database connection
func CloseDB() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			logger.Error("Error closing database", zap.Error(err))
		}
	}
}

// GetUserByUsername retrieves a user by their username
func GetUserByUsername(username string) (User, error) {
	var user User
	err := DB.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
	if err == sql.ErrNoRows {
		logger.Debug("User not found by username", zap.String("username", username))
		return User{}, fmt.Errorf("user not found")
	}
	if err != nil {
		logger.Error("DB error getting user by username", zap.Error(err), zap.String("username", username))
	}
	return user, err
}

// GetUserByID retrieves a user by their ID
func GetUserByID(id string) (User, error) {
	var user User
	err := DB.QueryRow("SELECT id, username, password FROM users WHERE id = ?", id).Scan(&user.ID, &user.Username, &user.Password)
	if err == sql.ErrNoRows {
		logger.Debug("User not found by ID", zap.String("user_id", id))
		return User{}, fmt.Errorf("user not found")
	}
	if err != nil {
		logger.Error("DB error getting user by ID", zap.Error(err), zap.String("user_id", id))
	}
	return user, err
}

// InsertUser inserts a new user into the database
func InsertUser(user User) error {
	_, err := DB.Exec("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", user.ID, user.Username, user.Password)
	if err != nil {
		logger.Error("DB error inserting user", zap.Error(err), zap.String("user_id", user.ID), zap.String("username", user.Username))
	}
	return err
}

// GetSessionByToken retrieves a session by its token
func GetSessionByToken(token string) (Session, error) {
	var session Session
	// Note: The second 'session.UserID' should be 'session.Token' in the Scan if your table design maps 'token' to 'user_id'
	// Corrected: Assuming 'token' is stored as the first column, and 'user_id' as the second.
	// You might have a typo here. Let's assume the order matches the table schema (token, user_id, expires_at).
	// If the table schema is (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at DATETIME NOT NULL),
	// then the Scan should be like: &session.Token, &session.UserID, &session.ExpiresAt
	// However, the current struct doesn't have a Token field for Session. Let's adjust to match.
	// Assuming the database table column `token` maps to the `Session` struct's `UserID` for lookup purpose.
	// This might be a design simplification from earlier; typically Session struct would have a `Token` field.
	// Let's ensure the `Scan` matches the SELECT statement and struct.
	// Looking at the Session struct: type Session struct { UserID string; ExpiresAt time.Time }
	// And the SQL: CREATE TABLE IF NOT EXISTS sessions ( token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at DATETIME NOT NULL );
	// So, the SELECT should be: SELECT token, user_id, expires_at FROM sessions...
	// And the Scan should be: &sessionTokenVar, &session.UserID, &session.ExpiresAt
	// Since GetSessionByToken returns a Session struct which doesn't store the token itself,
	// and the token is the lookup key, it's fine not to scan it into the struct.
	// However, the `Scan(&session.UserID, &session.UserID, &session.ExpiresAt)` is a typo, it should be `&someTokenVar, &session.UserID, &session.ExpiresAt`.
	// For simplicity, let's assume session.UserID is the first parameter in Scan to get the user ID.
	// But it's usually `token TEXT PRIMARY KEY`.
	// Let's correct this. A Session struct should ideally have a `Token` field.
	// For now, I'll modify the `Scan` based on the provided DB schema.

	var sessionTokenFromDB string // To scan the token column
	err := DB.QueryRow("SELECT token, user_id, expires_at FROM sessions WHERE token = ?", token).Scan(&sessionTokenFromDB, &session.UserID, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		logger.Debug("Session not found by token", zap.String("token", token))
		return Session{}, fmt.Errorf("session not found")
	}
	if err != nil {
		logger.Error("DB error getting session by token", zap.Error(err), zap.String("token", token))
	}
	return session, err
}

// InsertSession inserts a new session into the database
// InsertSession inserts a new session into the database
func InsertSession(session Session) error { // Now takes the full Session struct
	_, err := DB.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", session.Token, session.UserID, session.ExpiresAt)
	if err != nil {
		logger.Error("DB error inserting session", zap.Error(err), zap.String("session_token_prefix", session.Token[:5]), zap.String("user_id", session.UserID))
	}
	return err
}

// REVISION FOR SESSION MANAGEMENT:
// A common pattern is to have the Session struct *contain* its ID (token).
// Let's adjust the Session struct in main.go to include a Token field.
// This will necessitate a change to the `Session` struct itself.
// I will propose this change before this code block in main.go.

// If the Session struct is:
// type Session struct {
//     Token     string
//     UserID    string
//     ExpiresAt time.Time
// }
// Then the database functions should operate on this.

// Placeholder function - will be properly defined once Session struct is updated.
// For now, it will look like the below after the struct change.

// InsertSession inserts a new session into the database
func InsertSessionCorrected(session Session) error { // Renamed for clarity on change
	_, err := DB.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", session.Token, session.UserID, session.ExpiresAt)
	if err != nil {
		logger.Error("DB error inserting session", zap.Error(err), zap.String("session_token_prefix", session.Token[:5]), zap.String("user_id", session.UserID))
	}
	return err
}

// DeleteSessionByToken deletes a session by its token
func DeleteSessionByToken(token string) error {
	_, err := DB.Exec("DELETE FROM sessions WHERE token = ?", token)
	if err != nil {
		logger.Error("DB error deleting session by token", zap.Error(err), zap.String("token", token))
	}
	return err
}

// GetArticles retrieves all articles
func GetArticles() ([]Article, error) {
	rows, err := DB.Query("SELECT id, title, content, author_id, created_at, updated_at FROM articles ORDER BY created_at DESC")
	if err != nil {
		logger.Error("DB error getting all articles", zap.Error(err))
		return nil, err
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		if err := rows.Scan(&article.ID, &article.Title, &article.Content, &article.AuthorID, &article.CreatedAt, &article.UpdatedAt); err != nil {
			logger.Error("DB error scanning article row", zap.Error(err))
			return nil, err
		}
		articles = append(articles, article)
	}
	if err = rows.Err(); err != nil { // Check for errors during iteration
		logger.Error("DB error during rows iteration for articles", zap.Error(err))
	}
	return articles, rows.Err()
}

// GetArticleByID retrieves a single article by ID
func GetArticleByID(id string) (Article, error) {
	var article Article
	err := DB.QueryRow("SELECT id, title, content, author_id, created_at, updated_at FROM articles WHERE id = ?", id).Scan(&article.ID, &article.Title, &article.Content, &article.AuthorID, &article.CreatedAt, &article.UpdatedAt)
	if err == sql.ErrNoRows {
		logger.Debug("Article not found by ID", zap.String("article_id", id))
		return Article{}, fmt.Errorf("article not found")
	}
	if err != nil {
		logger.Error("DB error getting article by ID", zap.Error(err), zap.String("article_id", id))
	}
	return article, err
}

// InsertArticle inserts a new article into the database
func InsertArticle(article Article) error {
	_, err := DB.Exec("INSERT INTO articles (id, title, content, author_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		article.ID, article.Title, article.Content, article.AuthorID, article.CreatedAt, article.UpdatedAt)
	if err != nil {
		logger.Error("DB error inserting article", zap.Error(err), zap.String("article_id", article.ID), zap.String("title", article.Title))
	}
	return err
}

// UpdateArticle updates an existing article in the database
func UpdateArticle(article Article) error {
	_, err := DB.Exec("UPDATE articles SET title = ?, content = ?, updated_at = ? WHERE id = ?",
		article.Title, article.Content, article.UpdatedAt, article.ID)
	if err != nil {
		logger.Error("DB error updating article", zap.Error(err), zap.String("article_id", article.ID), zap.String("title", article.Title))
	}
	return err
}

// DeleteArticle deletes an article from the database
func DeleteArticle(id string) error {
	_, err := DB.Exec("DELETE FROM articles WHERE id = ?", id)
	if err != nil {
		logger.Error("DB error deleting article", zap.Error(err), zap.String("article_id", id))
	}
	return err
}