package models

/*
Author: Ayush Poudel
----------------------------
The below line is common in the definition of struct we will go over why are we using the code inside ``
FirstName    *string            `json:"first_name" validate:"required,min=2,max=100"`
These are called struct tags
                 -----------
Struct Tags
-----------
A struct tag is a string attached to a field
Everything inside backticks are just texts
Go does not execute it, interpret it or parse it
** Struct Tags are just metadata **

How Go Stores Struct Tags Internally
-------------------------------------
It stores this string as part of struct type
When a line like `json:"first_name" validate:"required,min=2,max=6"` is compiled
Go records it as:
		- key "json" value "first_name"
		- key "validate" value "required,min=2,max=6"
		-  {
				json: "first_name"
				validate: "required,min=2,max=6"
		   }
However, go itself does not do anything with it

How Struct Tags are Used
-------------------------
It is used with something called reflection
								------------
External libraries like (JSON, MongoDB, Validator etc) look a struct using reflection
Example:
	- Json encoder calls:
		field.Tag.Get("json")
	- Validator library calls:
		field.Tag.Get("validate")
	- MongoDB driver calls:
		field.Tag.Get("bson")

*/

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id"`
	FirstName    *string            `json:"first_name" validate:"required,min=2,max=100"`
	LastName     *string            `json:"last_name" validate:"required,min=2,max=100"`
	Email        *string            `json:"email" validate:"required,email"`
	Password     *string            `json:"password" validate:"required,min=6"`
	Phone        *string            `json:"phone" validate:"required"`
	Token        *string            `json:"token"`
	UserType     *string            `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	RefreshToken *string            `json:"refresh_token"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
	UserId       *string            `json:"user_id"`
}
