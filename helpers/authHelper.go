package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func CheckIfAdmin(c *gin.Context, role string) (err error) {
	err = nil
	if role != "ADMIN" {
		err = errors.New("Access to this resource required Admin priveleges")
	}
	return err
}

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("user_id")

	err = nil

	if userType == "USER" && uid != userId {
		err = errors.New("Unauthorized access to this resource.")
		return err
	}

	err = CheckIfAdmin(c, userType)
	return err

}
