package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/davecgh/go-spew/spew"
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

	pgUrl, err := pq.ParseURL("postgres://mksgbdex:FIxXAWueImfruyFj5EzESozrNRgBIgJZ@lallah.db.elephantsql.com:5432/mksgbdex")
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
	res.Write([]byte("login success"))
}
func ProtectedEndpoint(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("ProtectedEndpoint success"))
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Print("TokenVerifyMiddleWare")
	return nil
}

// func GenerateToken(user User) (string, error) {
// 	// var err Error
// 	// secret := "secret"
// 	jwt.
// }
