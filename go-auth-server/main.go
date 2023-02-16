package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"web_project_backend/users"
	"web_project_backend/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	secret = "supersecretkey"
)

var db *sql.DB
var exptime = 36000

type Login struct {
	EmailOrPhone string
	Password     string
}

type Register struct {
	Email        string
	Phone_number string
	Gender       string
	First_name   string
	Last_name    string
	Password     string
}

func main() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=alierfan dbname=postgres sslmode=disable")
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	fmt.Println(db)

	httpReq := mux.NewRouter()
	httpReq.Use(PanicHandler)
	httpReq.HandleFunc("/login", login).Methods("POST")
	httpReq.HandleFunc("/signup", register).Methods("POST")
	httpReq.HandleFunc("/user", profile).Methods("GET")
	httpReq.HandleFunc("/signout", signout).Methods("POST")
	httpReq.HandleFunc("/isTokenValid", isTokenValid).Methods("GET")
	print("App is working on port :3000\n")

	err = http.ListenAndServe(":3000", httpReq)
	if err != nil {
		log.Fatalf("Error starting the server: %v", err)
	}
}

func PanicHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			error := recover()
			if error != nil {
				log.Println(error)
				resp := utils.ErrResponse{Message: "Internal server error"}
				err := json.NewEncoder(w).Encode(resp)
				if err != nil {
					return
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func login(write http.ResponseWriter, read *http.Request) {

	var creds Login
	body, err1 := ioutil.ReadAll(read.Body)
	utils.HandleErr(err1)
	err := json.NewDecoder(read.Body).Decode(&creds)

	err2 := json.Unmarshal(body, &creds)
	utils.HandleErr(err2)
	if err2 != nil {
		http.Error(write, "Error decoding request body", http.StatusBadRequest)
		return
	}
	var id int
	var password string
	// Query the database to check if the user exists and the password is correct
	if utils.IsEmail(creds.EmailOrPhone) {

		err = db.QueryRow("SELECT user_id ,password_hash FROM user_account WHERE email=$1 ", creds.EmailOrPhone).Scan(&id, &password)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(write, " email or phone do not  exist", http.StatusUnauthorized)
				return
			}
			http.Error(write, err.Error(), http.StatusInternalServerError)
			return
		}

		passErr := bcrypt.CompareHashAndPassword([]byte(password), []byte(creds.Password))
		fmt.Println(passErr)
		if passErr != nil {
			err := json.NewEncoder(write).Encode(map[string]interface{}{"message": "password is incorrect."})
			if err != nil {
				return
			}
			write.WriteHeader(http.StatusCreated)
			return
		}
	} else if utils.IsPhoneValid(creds.EmailOrPhone) {

		err = db.QueryRow("SELECT user_id,password_hash FROM user_account WHERE phone_number=$1 ", creds.EmailOrPhone).Scan(&id, &password)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(write, "Username or password is incorrect", http.StatusUnauthorized)
				return
			}
			passErr := bcrypt.CompareHashAndPassword([]byte(password), []byte(creds.Password))
			fmt.Println(passErr)
			if passErr != nil {
				err := json.NewEncoder(write).Encode(map[string]interface{}{"message": "password is incorrect."})
				if err != nil {
					return
				}
				write.WriteHeader(http.StatusCreated)
				return
			}

			http.Error(write, "Error querying the database", http.StatusInternalServerError)
			return

		}
	}

	// Create the JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = id
	claims["exp"] = time.Now().Add(time.Second * time.Duration(exptime)).Unix()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		http.Error(write, "Error signing the token", http.StatusInternalServerError)
		return
	}

	write.Write([]byte(tokenString))
}

func register(write http.ResponseWriter, read *http.Request) {

	var creds Register
	body, err1 := ioutil.ReadAll(read.Body)
	utils.HandleErr(err1)

	err2 := json.Unmarshal(body, &creds)
	utils.HandleErr(err2)

	if !utils.IsEmailValid(creds.Email) {
		defer func(db *sql.DB) {
			err := db.Close()
			if err != nil {

			}
		}(db)
		err := json.NewEncoder(write).Encode(map[string]interface{}{"message": "email invalid"})
		if err != nil {
			return
		}
		write.WriteHeader(http.StatusCreated)

	} else if !utils.IsPhoneValid(creds.Phone_number) {
		defer func(db *sql.DB) {
			err := db.Close()
			if err != nil {

			}
		}(db)
		err := json.NewEncoder(write).Encode(map[string]interface{}{"message": "Phone numbers are 11 digits(09121234567)."})
		if err != nil {
			return
		}
		write.WriteHeader(http.StatusCreated)

	} else if !utils.IsGenderValid(creds.Gender) {
		defer db.Close()
		json.NewEncoder(write).Encode(map[string]interface{}{"message": "Gender must be F or M."})
		write.WriteHeader(http.StatusCreated)
	}
	// Insert the new user into the database
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 12)
	utils.HandleErr(err)
	var id int
	fmt.Println(creds.Gender)
	err = db.QueryRow("INSERT INTO user_account (email ,phone_number,gender ,first_name ,last_name ,password_hash) VALUES ($1, $2, $3,$4,$5,$6) RETURNING user_id", creds.Email, creds.Phone_number, creds.Gender, creds.First_name, creds.Last_name, hashpassword).Scan(&id)
	if err != nil {
		http.Error(write, err.Error(), http.StatusInternalServerError)
		http.Error(write, "Error inserting the user into the database", http.StatusInternalServerError)
		return
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": id,
	})

	_, err = token.SignedString([]byte(secret))
	if err != nil {
		http.Error(write, "Error signing the token", http.StatusInternalServerError)
		return
	}

	write.Write([]byte("user registered successfully"))
}
func profile(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	user := users.GetUserInfo(auth)
	resp := user
	json.NewEncoder(w).Encode(resp)
	w.WriteHeader(http.StatusCreated)
}

func isTokenValid(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	isValid, _ := utils.IsTokenValid(auth)

	_, isExpired := users.CheckCache(isValid, auth)
	fmt.Println(isExpired)
	if isExpired {
		w.Write([]byte("token is invalid"))
		return
	}
	if isValid != "" {
		w.Write([]byte(isValid))
		return
	} else {
		w.Write([]byte("token is invalid"))
	}

}

func signout(write http.ResponseWriter, read *http.Request) {

	auth := read.Header.Get("Authorization")
	signout := users.Signout(auth)
	resp := signout
	err := json.NewEncoder(write).Encode(resp)
	if err != nil {
		return
	}
	write.WriteHeader(http.StatusCreated)
}
