/*
Author: Ayush poudel
*/
/*
What are JWT Tokens?
-----------------------
Used in modern backend systems for valid authentication from frontend to backend or one API to other API. It is helful in a way
that it contains information like Email, Name, User Type and User Id of the user which can be helpful to check user permissions, scope,
and so on without having to query the database based on user's email only.

JWT is JSON Web Token, a compact, URL-safe, cryptographically signed string that encodes set of claims (data) in JSON so that server can verify
two things without talking to any other storage:
	1. Who the client is?
	2. Where the token has been tampered or expired.
It's defined by RFC 7519 as a standard way to represent claims between two parites (typically client and server) in a self-contained way.

A JWT Token consists of three parts
------------------------------------
HEADER.PAYLOAD/CLAIMS.SIGNATURE
1. HEADER: It contains info like how the string was signed (ex HS256, RS256 and so on) and type (ex JWT). It does not contain secrets but just tells which
algo was used
2. PAYLOAD/CLAIMS: A Json object containing actual facts the token conveys. Claims are of three categories
	a. Registered CLAIMS: Standarized fields like iss [issuer], sub [subject], aud [audience], exp [expireation], iat [issued at], nbf [not before].
	b. Public CLAIMS: Custom but documented fields
	c. Private CLAIMS: Fully custom fields agreed upon by the system. Ex: UserId, Email, Role, Plan.
3. SIGNATURE: A digital signature computed over base64 using secret key. It ensures if anobody distorts the contents of JWT backend invalidates the token

What it does in practice?
-------------------------------
In an authentication/authorization context a typical access JWT contains enough information for the backend to make access decisions without hitting a
database on every request. Common Contents are:
	1. A stable identifier: sub or user_id
	2. Identity Info: email, name, username
	3. Authorization Info: role, permissions, scopes
	4. Validity Metadata: exp, iat, nbf, iss, aud
It does not contain/ should not contain any secrets like password, API keys, credit card details or any other sensitive information because JWT is signed,
not encrypted; anyone who intercepts it can decode the header and payload and read their contents. What they cannot do is modify them and still produce a
valid signature without the key.

Why was JWT built / what problem does it solve?
------------------------------------------------
Before JWT and similar token standards, many systems used server-side sessions.
	1. User logs in; server creates a random session ID.
	2. Server stores session data in memory or a database keyed by that ID.
	3. Client stores the session ID in a cookie.
	4. Every request: client sends session ID; server looks up data from its session store.
This approach is stateful: the server must maintain a session store and share it between nodes (think Redis or sticky sessions).
That gets messy with:
	1. Horizontally scaled APIs (lots of app servers)
	2. Microservices (multiple independent services)
	3. Mobile apps and SPAs that talk directly to APIs
JWT was built to turn that into a stateless model:
	1. At login, server verifies credentials once.
	2. Server issues a JWT that encodes the claims (user ID, role, expiration) and signs it.
	3. Client stores the JWT.
	4. On each subsequent request, client sends the JWT (usually in Authorization: Bearer <token>).
Server does not need a session store. It just:
	1. Verifies the signature with the known key,
	2. Checks standard claims like exp, iss, aud,
	3. Reads claims like user_id and role directly from the token.
*/

/*
What this Code does?
--------------------
This file is reponsible for generating both Access Tokens and Refresh Token for a user when they successfully sign up or login.
It does the following:
1. Defines a signed details struct represents the payload/claims stored inside it.
	It includes:
		- Email, UserId, FirstName, LastName, UserType, UserId
		- Standard JWT Fields such as expiration time though embedded jwt.StandardClaims
2. It retrieves secret key from environment using getJwtSecret() function. This is used to sign tokens cryptographically
3. The GenerateAllTokens function creates both Access Token and Refresh Token.
4. The function returns both tokens along with any error messages.
*/

package helpers

import (
	"log"
	"os"
	"time"

	"github.com/ayuspoudel/go-jwt-auth-service/database"
	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/mongo"
)

/*
This is a claim. It contains all info we want to store in it along side with jwt.StandardClaims. This will be passed into NewWithClaims() method as an
attribute because that method is provided by golang's jwt package and requires standard claims to be passed onto along with Private Claims, like ours which
are Email, FirstName, LastName and so on. But it definately needs a jwt.StandardClaims field inside the struct.
*/
type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	UserType  string
	UserId    string
	jwt.StandardClaims
}

/*
We are getting userCollection from DB just in case we might need it using our function OpenCollection already defined in /database/databaseController.go
*/
var userCollection *mongo.Collection = database.OpenCollection("user")

// This function will get JWT_SECRET_KEY from the env
func getJwtSecret() string {
	key := os.Getenv("JWT_SECRET_KEY")
	if key == "" {
		log.Fatal("JWT_SECRET_KEY not found in environment variables")
	}
	return key
}

// This function will generate both Access Token and Refresh Token

func GenerateAllTokens(email string,
	firstName string,
	lastName string,
	userType string,
	userId string) (signedToken string, signedRefreshToken string, err error) {

	/*
		Creating a struct of type SignedDetails and passing our Private CLAIMS into it as defined above
		This will automatically create a new struct and claims will contain a pointer to the address of that struct
		The function which we will later use called NewWithClaims() requires us to pass an address of the struct rather than whole struct
		It is very common in go, because in go, we tend to avoid copying large data structures and instead using same underlying memory
	*/
	claims := &SignedDetails{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		UserType:  userType,
		UserId:    userId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	/*
		This is another struct and again returns a pointer to claims struct that we are creating.
		This does not need to contain all the private claims as it will be used to issue another access token - will be passed by frontend in case access token expires.
	*/
	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	// Getting the secret key from env
	var SECRET_KEY string = getJwtSecret()

	/*
		This line will get the token. This is the famous function we have been talking about NetWithClaims() provided by jwt package we have imported
		It takes claims and returns unsigned token.
		For example:
			If our input of claims was
			**************************************************
			&SignedDetails
				{
					UserEmail: ayushpoudel@usf.edu
					UserType: "ADMIN"
					StandardClaims: jwt.StandardClaims{
										ExpiresAt: 170000000
									}
				},
			**************************************************

			Then it will return:

			**************************************************
				&jwt.Token{
					Raw: "", 								// not signed/encoded yet
					Method: &SigningMethodHMAC{}			// Signing method specified
					Header: map[string]interface{}{
						"alg": "HS256",
						"typ": "JWT",
					},
					Claims: &SignedDetails{
						UserEmail: ayushpoudel@usf.edu
						UserType: "ADMIN"
						StandardClaims: jwt.StandardClaims{
										ExpiresAt: 170000000
									},
					},
					Signature: "",							// Not a signature yet
					Valid: false							// Not validated yet
			******************************************************
	*/
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // Commented Above |
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	signedToken, err = token.SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}

	signedRefreshToken, err = refreshToken.SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}
	return signedToken, signedRefreshToken, nil
}
