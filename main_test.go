package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestMain sets up and tears down the database for all tests.
// This function runs once before all tests in the package.
func TestMain(m *testing.M) {
	// Initialize a temporary in-memory SQLite database for testing
	// This ensures tests are isolated and don't affect the real data.
	InitDB("file::memory:?cache=shared") // In-memory SQLite DB
	
	// Run all tests
	code := m.Run()

	// Clean up after tests (optional for in-memory, but good practice)
	CloseDB() 
	
	// Exit with the test result code
	os.Exit(code)
}

// TestRegisterUser tests the /api/register endpoint.
func TestRegisterUser(t *testing.T) {
	// Clear existing users from the DB for isolated test
	// In a real scenario, you'd have more sophisticated test data setup/teardown per test
	DB.Exec("DELETE FROM users") 

	// Test Case 1: Valid registration
	validUser := map[string]string{
		"username": "testuser_valid",
		"password": "ValidP@ss1",
	}
	body, _ := json.Marshal(validUser)
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Call the handler directly
	registerUser(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Check the response body
	var res map[string]string
	json.NewDecoder(rr.Result().Body).Decode(&res)
	if res["message"] != "User registered successfully" {
		t.Errorf("handler returned unexpected message: got %v want %v", res["message"], "User registered successfully")
	}
	if res["id"] == "" {
		t.Errorf("handler returned empty user ID")
	}

	// Test Case 2: Duplicate username
	req = httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(body)) // Same user data
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	registerUser(rr, req)

	if status := rr.Code; status != http.StatusConflict {
		t.Errorf("handler returned wrong status code for duplicate user: got %v want %v", status, http.StatusConflict)
	}
	json.NewDecoder(rr.Result().Body).Decode(&res)
	if res["error"] != "Username already exists" {
		t.Errorf("handler returned unexpected error message for duplicate user: got %v want %v", res["error"], "Username already exists")
	}

	// Test Case 3: Invalid password (too short)
	invalidPassUser := map[string]string{
		"username": "testuser_shortpass",
		"password": "short", // Invalid password
	}
	body, _ = json.Marshal(invalidPassUser)
	req = httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	registerUser(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code for invalid password: got %v want %v", status, http.StatusBadRequest)
	}
	json.NewDecoder(rr.Result().Body).Decode(&res)
	if res["error"] != "Password must be at least 8 characters long." {
		t.Errorf("handler returned unexpected error message for invalid password: got %v want %v", res["error"], "Password must be at least 8 characters long.")
	}
}

// TestLoginUser tests the /api/login endpoint.
func TestLoginUser(t *testing.T) {
	// Ensure a user exists for login
	DB.Exec("DELETE FROM users") // Clear for test isolation
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("LoginP@ss1"), bcrypt.DefaultCost)
	InsertUser(User{ID: "loginuser_id", Username: "loginuser", Password: string(hashedPass)})

	// Test Case 1: Successful login
	credentials := map[string]string{
		"username": "loginuser",
		"password": "LoginP@ss1",
	}
	body, _ := json.Marshal(credentials)
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	loginUser(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code for successful login: got %v want %v", status, http.StatusOK)
	}
	var res map[string]string
	json.NewDecoder(rr.Result().Body).Decode(&res)
	if res["message"] != "Login successful" {
		t.Errorf("handler returned unexpected message for successful login: %v", res["message"])
	}
	if rr.Result().Header.Get("Set-Cookie") == "" {
		t.Errorf("Set-Cookie header not found for successful login")
	}

	// Test Case 2: Invalid password
	invalidCredentials := map[string]string{
		"username": "loginuser",
		"password": "WrongPassword",
	}
	body, _ = json.Marshal(invalidCredentials)
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	loginUser(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code for invalid password: got %v want %v", status, http.StatusUnauthorized)
	}
	json.NewDecoder(rr.Result().Body).Decode(&res)
	if res["error"] != "Invalid username or password" {
		t.Errorf("handler returned unexpected error message for invalid password: %v", res["error"])
	}

	// Test Case 3: Non-existent username
	nonExistentCredentials := map[string]string{
		"username": "nonexistent",
		"password": "AnyPassword123",
	}
	body, _ = json.Marshal(nonExistentCredentials)
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	loginUser(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code for non-existent user: got %v want %v", status, http.StatusUnauthorized)
	}
}

// TestCreateArticle tests the /api/articles POST endpoint with authentication.
func TestCreateArticle(t *testing.T) {
	// Setup: Register and login a user to get an authenticated request context.
	DB.Exec("DELETE FROM users") // Clear users for test isolation
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("AuthP@ss1"), bcrypt.DefaultCost)
	testUser := User{ID: "authuser_id", Username: "authuser", Password: string(hashedPass)}
	InsertUser(testUser)

	sessionToken := generateSessionToken()
	InsertSession(Session{UserID: testUser.ID, ExpiresAt: time.Now().Add(time.Hour)})

	// Test Case 1: Valid article creation
	validArticle := map[string]string{
		"title":   "My Test Article",
		"content": "This is some test content for the article, it's long enough.",
	}
	body, _ := json.Marshal(validArticle)
	
	// Create a request with the necessary cookie and context
	req := httptest.NewRequest(http.MethodPost, "/api/articles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
	
	rr := httptest.NewRecorder()

	// Wrap createArticle handler with authMiddleware for testing
	// This simulates how it's handled by the Mux router
	authMiddleware(http.HandlerFunc(createArticle)).ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code for valid article: got %v want %v. Response: %s", status, http.StatusCreated, rr.Body.String())
	}
	var createdArticle Article
	json.NewDecoder(rr.Result().Body).Decode(&createdArticle)
	if createdArticle.Title != validArticle["title"] {
		t.Errorf("handler returned unexpected article title: got %v want %v", createdArticle.Title, validArticle["title"])
	}
	if createdArticle.AuthorID != testUser.ID {
		t.Errorf("handler returned wrong author ID: got %v want %v", createdArticle.AuthorID, testUser.ID)
	}

	// Test Case 2: Invalid article (title too short)
	invalidArticle := map[string]string{
		"title":   "Bad",
		"content": "This is valid content.",
	}
	body, _ = json.Marshal(invalidArticle)
	req = httptest.NewRequest(http.MethodPost, "/api/articles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken}) // Still authenticated
	rr = httptest.NewRecorder()

	authMiddleware(http.HandlerFunc(createArticle)).ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code for invalid article title: got %v want %v", status, http.StatusBadRequest)
	}
	var res map[string]string
	json.NewDecoder(rr.Result().Body).Decode(&res)
	if res["error"] != "Article title must be between 5 and 100 characters long." {
		t.Errorf("handler returned unexpected error message for invalid title: %v", res["error"])
	}

	// Test Case 3: Unauthenticated request
	unauthReq := httptest.NewRequest(http.MethodPost, "/api/articles", bytes.NewBuffer(body))
	unauthReq.Header.Set("Content-Type", "application/json")
	unauthRr := httptest.NewRecorder()

	authMiddleware(http.HandlerFunc(createArticle)).ServeHTTP(unauthRr, unauthReq)

	if status := unauthRr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code for unauthenticated request: got %v want %v", status, http.StatusUnauthorized)
	}
	json.NewDecoder(unauthRr.Result().Body).Decode(&res)
	if res["error"] != "Missing authentication token. Please log in." {
		t.Errorf("handler returned unexpected error message for unauthenticated request: %v", res["error"])
	}
}

// TestGetArticles tests the /api/articles GET endpoint.
func TestGetArticles(t *testing.T) {
	// Setup: Clear existing articles and insert a few for testing.
	DB.Exec("DELETE FROM articles")
	InsertArticle(Article{
		ID: "article_test_1", Title: "Test Article 1", Content: "Content 1. Enough chars.",
		AuthorID: "author_id_1", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	InsertArticle(Article{
		ID: "article_test_2", Title: "Test Article 2", Content: "Content 2. Enough chars.",
		AuthorID: "author_id_2", CreatedAt: time.Now().Add(time.Minute), UpdatedAt: time.Now().Add(time.Minute),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/articles", nil)
	rr := httptest.NewRecorder()

	getArticles(rr, req) // Call the public handler directly

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var articles []Article
	json.NewDecoder(rr.Result().Body).Decode(&articles)

	if len(articles) != 2 {
		t.Errorf("handler returned wrong number of articles: got %v want %v", len(articles), 2)
	}
	// Check if articles are sorted correctly (by created_at DESC)
	if articles[0].ID != "article_test_2" || articles[1].ID != "article_test_1" {
        t.Errorf("articles not returned in expected order. Got: %v", articles)
    }
}

// TestUpdateArticle tests the /api/articles/{id} PUT endpoint.
func TestUpdateArticle(t *testing.T) {
    // Setup:
    // 1. Create a user
    DB.Exec("DELETE FROM users")
    DB.Exec("DELETE FROM articles")
    hashedPass, _ := bcrypt.GenerateFromPassword([]byte("UpdateP@ss1"), bcrypt.DefaultCost)
    testUser := User{ID: "updateuser_id", Username: "updateuser", Password: string(hashedPass)}
    InsertUser(testUser)

    // 2. Create an article by that user
    articleToUpdate := Article{
        ID: "update_article_id", Title: "Original Title", Content: "Original content for the article.",
        AuthorID: testUser.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
    }
    InsertArticle(articleToUpdate)

    // 3. Create a session for the user
    sessionToken := generateSessionToken()
    InsertSession(Session{UserID: testUser.ID, ExpiresAt: time.Now().Add(time.Hour)})

    // Test Case 1: Successful update by author
    updatePayload := map[string]string{
        "title":   "Updated Title",
        "content": "Updated content for the article, this is new.",
    }
    body, _ := json.Marshal(updatePayload)
    req := httptest.NewRequest(http.MethodPut, "/api/articles/update_article_id", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
    rr := httptest.NewRecorder()

    authMiddleware(http.HandlerFunc(updateArticle)).ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code for successful update: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
    }
    var updatedArticle Article
    json.NewDecoder(rr.Result().Body).Decode(&updatedArticle)
    if updatedArticle.Title != updatePayload["title"] || updatedArticle.Content != updatePayload["content"] {
        t.Errorf("article fields not updated correctly. Got %+v", updatedArticle)
    }

    // Test Case 2: Update an article owned by another user (Forbidden)
    DB.Exec("DELETE FROM users WHERE id != ?", testUser.ID) // Remove other users for clean test, but keep testUser
    otherUser := User{ID: "otheruser_id", Username: "otheruser", Password: string(hashedPass)}
    InsertUser(otherUser)
    
    otherArticle := Article{
        ID: "other_article_id", Title: "Other's Title", Content: "Other's content.",
        AuthorID: otherUser.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
    }
    InsertArticle(otherArticle)

    req = httptest.NewRequest(http.MethodPut, "/api/articles/other_article_id", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken}) // Still logged in as testUser
    rr = httptest.NewRecorder()

    authMiddleware(http.HandlerFunc(updateArticle)).ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusForbidden {
        t.Errorf("handler returned wrong status code for unauthorized update: got %v want %v", status, http.StatusForbidden)
    }
    var res map[string]string
    json.NewDecoder(rr.Result().Body).Decode(&res)
    if res["error"] != "You are not authorized to update this article" {
        t.Errorf("handler returned unexpected error message for unauthorized update: %v", res["error"])
    }
}

// TestDeleteArticle tests the /api/articles/{id} DELETE endpoint.
func TestDeleteArticle(t *testing.T) {
    // Setup:
    // 1. Create a user
    DB.Exec("DELETE FROM users")
    DB.Exec("DELETE FROM articles")
    hashedPass, _ := bcrypt.GenerateFromPassword([]byte("DeleteP@ss1"), bcrypt.DefaultCost)
    testUser := User{ID: "deleteuser_id", Username: "deleteuser", Password: string(hashedPass)}
    InsertUser(testUser)

    // 2. Create an article by that user
    articleToDelete := Article{
        ID: "delete_article_id", Title: "Delete Me", Content: "This article is for deletion.",
        AuthorID: testUser.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
    }
    InsertArticle(articleToDelete)

    // 3. Create a session for the user
    sessionToken := generateSessionToken()
    InsertSession(Session{UserID: testUser.ID, ExpiresAt: time.Now().Add(time.Hour)})

    // Test Case 1: Successful deletion by author
    req := httptest.NewRequest(http.MethodDelete, "/api/articles/delete_article_id", nil)
    req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
    rr := httptest.NewRecorder()

    authMiddleware(http.HandlerFunc(deleteArticle)).ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusNoContent {
        t.Errorf("handler returned wrong status code for successful delete: got %v want %v. Body: %s", status, http.StatusNoContent, rr.Body.String())
    }

    // Verify deletion from DB
    _, err := GetArticleByID(articleToDelete.ID)
    if err == nil || err != sql.ErrNoRows {
        t.Errorf("article was not deleted from database: got %v", err)
    }

    // Test Case 2: Delete an article owned by another user (Forbidden)
    otherUser := User{ID: "anotheruser_id", Username: "anotheruser", Password: string(hashedPass)}
    InsertUser(otherUser)
    
    otherArticle := Article{
        ID: "another_article_id", Title: "Don't Delete Me", Content: "I belong to another.",
        AuthorID: otherUser.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
    }
    InsertArticle(otherArticle)

    req = httptest.NewRequest(http.MethodDelete, "/api/articles/another_article_id", nil)
    req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken}) // Still logged in as testUser
    rr = httptest.NewRecorder()

    authMiddleware(http.HandlerFunc(deleteArticle)).ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusForbidden {
        t.Errorf("handler returned wrong status code for unauthorized delete: got %v want %v", status, http.StatusForbidden)
    }
    var res map[string]string
    json.NewDecoder(rr.Result().Body).Decode(&res)
    if res["error"] != "You are not authorized to delete this article" {
        t.Errorf("handler returned unexpected error message for unauthorized delete: %v", res["error"])
    }
}