/*
Author: Ayush Poudel
---------------------
The userController.go file contains all controller functions responsible for handling
user-related HTTP requests. These controllers act as the communication layer between
HTTP clients (frontend/API consumers), the User model, and the database.

The controllers included in this file are:
    - Signup()
    - Login()
    - GetUsers()
    - GetUser()

Each function below has its own internal documentation explaining exactly what it does.
Dependencies used by these controllers:
	1. database.OpenCollection(...)
	    - Used to get the MongoDB collection handle for performing DB CRUD operations.
	2. helpers.GenerateAllTokens(...)
	    - Generates JWT access and refresh tokens when user signs up or logs in
	3. helpers.UpdateAllTokens(...)
	    - Updates tokens in the database for the logged-in user
	4. helpers.MatchUserTypeToUid(...)
	    - Checks authorization. Only admin or the same user can access a restricted route.

External packages used:
	- context
	    Used to ensure DB operations do not hang forever by providing timeout/cancellation.
	- bcrypt (golang.org/x/crypto/bcrypt)
	    Used for secure password hashing:
	        - GenerateFromPassword()    :    hash and salt user passwords
	        - CompareHashAndPassword()  :    verify login password
	- gin (github.com/gin-gonic/gin)
	    Go web framework used for:
	        - JSON binding:    c.BindJSON()
	        - Getting params:  c.Param()
	        - Responding:      c.JSON()
	- validator (github.com/go-playground/validator/v10)
	    Used to validate incoming JSON payloads against User model struct tags.
	- mongo driver (go.mongodb.org/mongo-driver)
	    Used to perform database operations:
	        - CountDocuments()
	        - InsertOne()
	        - FindOne()
	        - Decode()
	        - etc.

Summary:
This controller handles user authentication and management features like
sign-up, login, retrieving a single user, and retrieving multiple users (coming soon).
It ensures secure password handling, JWT generation, and role-based access control.
*/

package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ayuspoudel/go-jwt-auth-service/database"
	"github.com/ayuspoudel/go-jwt-auth-service/helpers"
	"github.com/ayuspoudel/go-jwt-auth-service/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Create a user collection variable of type mongo.Collection using our OpenCollection() function defined in databaseConnection.go
var userCollection *mongo.Collection = database.OpenCollection("user")

// Create a validate instance from validator to validate *gin.Context() which are the payloads against our UserModel
var validate = validator.New()

// Password Helper function
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

// Password verify function
func VerifyPassword(userPassword string, providedPassword string) (passwordIsValid bool, msg string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	passwordIsValid = true
	if err != nil {
		msg = fmt.Sprintf("Login or Password is incorrect")
		passwordIsValid = false
	}
	return
}

// Signup function
func Signup() gin.HandlerFunc {
	/*
		SignUp functionality:
			1. Create struct
			2. Bind the *gin.Context() to user struct
			3. Validate the struct using validator package
			4. Check if email or phone already exists in DB
			5. If not insert the User struct into DB, by updating all values of User Model which is not inputted by user like Tokens, CreatedAt, Password and so on
			6. Generate tokens for the user using helper functions
	*/
	return func(c *gin.Context) {
		// Creating context so we can exit if anything hangs using context package
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second) // Adding context for 100s
		defer cancel()

		// Creating struct, so each http request gets its own struct
		var user models.User
		// Passing struct address to get everything from *gin.Context c to be put into user struct
		// From this line we get everything coming to this API into user struct
		err := c.BindJSON(&user)

		// The BindJSON function will throw any error if exists
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		/* Validate function that we created using validator package will validate if the user struct we just filled with payload is valid according to
		our struct or not*/
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		}
		// Counting email if already exist in DB
		emailCount, emailErr := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if emailErr != nil {
			log.Panic(emailErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occured while checking for the email"})
		}
		password := HashPassword(*user.Password)
		user.Password = &password
		// Counting phone if already exists in DB
		phoneCount, phoneErr := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if phoneErr != nil {
			log.Panic(phoneErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occured while checking for the phone"})
		}
		// If it does we dont create the user
		if emailCount > 0 || phoneCount > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This email or phone number already exists"})
			return
		}

		// Now we are writing the fields in struct which our app has to generate (or the ones that user don't pass via API call)
		user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Id = primitive.NewObjectID()
		user.UserId = user.Id.Hex()
		token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.FirstName, *user.LastName, *user.UserType, *&user.UserId)
		user.Token = &token
		user.RefreshToken = &refreshToken

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertionNumber)
	}

}

func Login() gin.HandlerFunc {
	/*
		Login Functionality is simple
			1. Takes the payload puts it in user
			2. Creates another foundUser struct by quering the collection based on user.Email
			3. Checks if we can find the user who is trying to login, if not return error
			4. Verifies the password using VerifyPassword() function defined above
			5. If everything is okay, generate new JWT tokens for the user
	*/
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		// Create user (Usermodel srtuct data structure) - we will store the payload from *gin.Context() in here
		var user models.User
		// Create foundUser to track the user we find in db from userCollection.FindOne() function call
		var foundUser models.User
		//Put c *gin.Context into user
		err := c.BindJSON(&user)
		// Check if this throws any error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Find the user in collection
		finderr := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if finderr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login or Password is incorrect"})
			return
		}
		// Check if we can find the user in the collection as well
		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}
		// Verify the password recieved from payload and what we have found in collection
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		// If password is invalid return
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		}
		/*
			If everything is okay, we generate new JWT tokens for the user
			func GenerateAllTokens(email string, firstName string, lastName string, userType string, userId string)
		*/

		token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, *foundUser.UserType, *&foundUser.UserId)
		helpers.UpdateAllTokens(token, refreshToken, foundUser.UserId)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.UserId}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := helpers.CheckUserType(c, "ADMIN")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}
		startIndex := (page - 1) * recordPerPage
		startIndexStr, _ := strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{{_id}}}}

	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		/*
			Get User:
				1. Get userId from *gin.Context using .Param("PARAMETER")
				2. Only the user himself or an admin should be able to access this API
				3. Check if MatchUserTypeToUid is true, else return with not authorized to access error
				4. Check if user is Admin (which is done inside the MatchUserTypeToUid function itself)
				5. If everything is okay, find the user from collection and return
		*/
		userId := c.Param("user_id")

		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second) // Adding context for 100s
		defer cancel()

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occured while fetching the user"})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
