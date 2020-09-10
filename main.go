package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/labstack/gommon/log"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json"password"`
}
type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {

	pgUrl, err := pq.ParseURL(os.Getenv("POSTGRES_USER_DB"))
	if err != nil {
		log.Fatal(err)
	}
	db, err = sql.Open("postgres", pgUrl)

	fmt.Print(db)

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(ProtectedEndpoint)).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}

func signup(res http.ResponseWriter, req *http.Request) {
	var user User
	var e Error
	json.NewDecoder(req.Body).Decode(&user)
	fmt.Print(user)
	spew.Dump(user)

	if user.Email == "" {
		e.Message = "email missing"
		respondWithError(res, http.StatusBadRequest, e)
		return
	}
	if user.Password == "" {
		e.Message = "password missing"
		respondWithError(res, http.StatusBadRequest, e)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
		return
	}
	user.Password = string(hash)
	stmt := "insert into users (email,password) values($1,$2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		e.Message = err.Error()
		respondWithError(res, http.StatusInternalServerError, e)
	}
	user.Password = ""
	res.Header().Set("Content-type", "applicationn/json")
	responseJSON(res, user)
}
func responseJSON(res http.ResponseWriter, data interface{}) {
	json.NewEncoder(res).Encode(data)
}
func respondWithError(res http.ResponseWriter, status int, e Error) {
	res.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(res).Encode(e)
}
func login(res http.ResponseWriter, req *http.Request) {
	var user User
	var jwt JWT
	var error Error

	json.NewDecoder(req.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(res, http.StatusBadRequest, error)
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(res, http.StatusBadRequest, error)
	}
	password := user.Password
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "user does not exist"
			respondWithError(res, http.StatusBadRequest, error)
		} else {
			log.Fatal(err)
		}
	}

	hashed := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err != nil {
		error.Message = "invalid password"
		respondWithError(res, http.StatusUnauthorized, error)
		return
	}
	token, err := GenerateToken(user)
	jwt.Token = token
	if err != nil {
		log.Fatal(err)
	}
	res.WriteHeader(http.StatusOK)
	responseJSON(res, jwt)
}
func ProtectedEndpoint(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("ProtectedEndpoint success"))
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		var errorObj Error
		authHeader := req.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte("secret"), nil
			})
			if error != nil {
				errorObj.Message = error.Error()
				respondWithError(res, http.StatusUnauthorized, errorObj)
				return
			}
			if token.Valid {
				next.ServeHTTP(res, req)
			} else {
				errorObj.Message = error.Error()
				respondWithError(res, http.StatusUnauthorized, errorObj)
				return
			}
		} else {
			errorObj.Message = "Invalid token."
			respondWithError(res, http.StatusUnauthorized, errorObj)
			return
		}
	})
}

func GenerateToken(user User) (string, error) {
	// var err Error
	secret := "secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "Course",
	})
	spew.Dump(token)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}
	return tokenString, nil
}
