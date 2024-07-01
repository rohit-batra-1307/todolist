package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/thedevsaddam/renderer"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	rnd             *renderer.Render
	db              *mongo.Collection
	usersCollection *mongo.Collection

	dbName              = "demo_todo"
	collectionName      = "todos"
	usersCollectionName = "users"
	port                = ":9020"
	connectionString    = "mongodb+srv://skywalkerbatra:qyeOdRtc8LvfyKcx@cluster0.dzgyuzd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
	jwtKey              = []byte("your_secret_key")
)

type (
	User struct {
		ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
		Username string             `json:"username"`
		Password string             `json:"password"`
	}
	Todo struct {
		ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
		UserID      string             `bson:"user_id" json:"user_id"`
		Title       string             `bson:"title" json:"title"`
		Description string             `bson:"description" json:"description"`
		Status      string             `bson:"status" json:"status"`
		CreatedAt   time.Time          `bson:"createdAt" json:"created_at"`
		UpdatedAt   time.Time          `bson:"updatedAt" json:"updated_at"`
	}
	Claims struct {
		Username string `json:"username"`
		jwt.StandardClaims
	}
)

func init() {
	rnd = renderer.New(renderer.Options{
		ParseGlobPattern: "static/*.tpl",
	})

	clientOptions := options.Client().ApplyURI(connectionString)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	db = client.Database(dbName).Collection(collectionName)
	usersCollection = client.Database(dbName).Collection(usersCollectionName)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the username already exists
	existingUser := getUserByUsername(user.Username)
	if existingUser != nil {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	// Insert the user into the database
	_, err = usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Find the user in the database
	storedUser := getUserByUsername(user.Username)
	if storedUser == nil || storedUser.Password != user.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	tokenString, err := generateToken(user.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set token as cookie
	expirationTime := time.Now().Add(24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		tokenStr := cookie.Value
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Store the username in the context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SignUpPageHandler(w http.ResponseWriter, r *http.Request) {
	err := rnd.HTML(w, http.StatusOK, "signup.tpl", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	err := rnd.HTML(w, http.StatusOK, "login.tpl", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func pageHandler(w http.ResponseWriter, r *http.Request) {
	err := rnd.HTML(w, http.StatusOK, "page.tpl", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func todoHandlers() http.Handler {
	rg := chi.NewRouter()
	rg.Group(func(r chi.Router) {
		r.Use(authMiddleware) // Apply the auth middleware
		r.Get("/", fetchTodos)
		r.Post("/", createTodo)
		r.Put("/{id}", updateTodo)
		r.Delete("/{id}", deleteTodo)
	})
	return rg
}

func fetchTodos(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	user := getUserByUsername(username)
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	var todos []Todo
	cursor, err := db.Find(context.TODO(), bson.M{"user_id": user.ID.Hex()})
	if err != nil {
		rnd.JSON(w, http.StatusInternalServerError, renderer.M{
			"message": "Failed to fetch todos",
			"error":   err.Error(),
		})
		return
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var t Todo
		err := cursor.Decode(&t)
		if err != nil {
			rnd.JSON(w, http.StatusInternalServerError, renderer.M{
				"message": "Failed to decode todo",
				"error":   err.Error(),
			})
			return
		}
		todos = append(todos, t)
	}

	if err := cursor.Err(); err != nil {
		rnd.JSON(w, http.StatusInternalServerError, renderer.M{
			"message": "Cursor error",
			"error":   err.Error(),
		})
		return
	}

	rnd.JSON(w, http.StatusOK, renderer.M{
		"data": todos,
	})
}

func createTodo(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	user := getUserByUsername(username)
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	var t Todo
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		rnd.JSON(w, http.StatusBadRequest, renderer.M{
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
		return
	}

	t.ID = primitive.NewObjectID()
	t.UserID = user.ID.Hex()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	_, err := db.InsertOne(context.TODO(), t)
	if err != nil {
		rnd.JSON(w, http.StatusInternalServerError, renderer.M{
			"message": "Failed to insert todo",
			"error":   err.Error(),
		})
		return
	}

	// Return the newly created TODO item in the response
	rnd.JSON(w, http.StatusCreated, renderer.M{
		"message": "Todo created successfully",
		"todo":    t,
	})
}

func updateTodo(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	user := getUserByUsername(username)
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	id := chi.URLParam(r, "id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		rnd.JSON(w, http.StatusBadRequest, renderer.M{
			"message": "Invalid todo ID",
			"error":   err.Error(),
		})
		return
	}

	var t Todo
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		rnd.JSON(w, http.StatusBadRequest, renderer.M{
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
		return
	}

	update := bson.M{
		"$set": bson.M{
			"title":       t.Title,
			"description": t.Description,
			"status":      t.Status,
			"updatedAt":   time.Now(),
		},
	}

	_, err = db.UpdateOne(context.TODO(), bson.M{"_id": objID, "user_id": user.ID.Hex()}, update)
	if err != nil {
		rnd.JSON(w, http.StatusInternalServerError, renderer.M{
			"message": "Failed to update todo",
			"error":   err.Error(),
		})
		return
	}

	// Call fetchTodos to update the list after updating the todo
	fetchTodos(w, r)
}

func deleteTodo(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	user := getUserByUsername(username)
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	id := chi.URLParam(r, "id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		rnd.JSON(w, http.StatusBadRequest, renderer.M{
			"message": "Invalid todo ID",
			"error":   err.Error(),
		})
		return
	}

	_, err = db.DeleteOne(context.TODO(), bson.M{"_id": objID, "user_id": user.ID.Hex()})
	if err != nil {
		rnd.JSON(w, http.StatusInternalServerError, renderer.M{
			"message": "Failed to delete todo",
			"error":   err.Error(),
		})
		return
	}

	// Call fetchTodos to update the list after deleting the todo
	fetchTodos(w, r)
}

func getUserByUsername(username string) *User {
	var user User
	err := usersCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	r.Get(path+"*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

func main() {
	stopChan := make(chan os.Signal, 1) // Buffered channel with size 1
	signal.Notify(stopChan, os.Interrupt)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", pageHandler)

	r.Mount("/todo", todoHandlers())

	r.Get("/signup", SignUpPageHandler)
	r.Post("/signup", RegisterHandler)
	r.Get("/login", LoginPageHandler)
	r.Post("/login", LoginHandler)

	// Serve static files from the "static" directory
	staticDir := "./static"
	FileServer(r, "/static", http.Dir(staticDir))

	srv := &http.Server{
		Addr:         port,
		Handler:      r,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Println("Listening on port", port)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("Server gracefully stopped!")
}
