package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ayuspoudel/go-jwt-auth-service/database"
	"github.com/ayuspoudel/go-jwt-auth-service/helpers"
	"github.com/ayuspoudel/go-jwt-auth-service/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func HashPassword() {

}

var userCollection *mongo.Collection = database.OpenCollection("user")
var validate = validator.New()

func VerifyPassword() {

}

func Signup() gin.HandlerFunc {
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
		return
	}

}

func Login()

func GetUsers()

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
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
