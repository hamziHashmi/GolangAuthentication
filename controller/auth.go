package controllers

import (
	"net/http"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/hamziHashmi/GolangAuthentication/models"
	"github.com/hamziHashmi/GolangAuthentication/utils"
)

func CurrentUser(c *gin.Context) {

	user_id, err := utils.ExtractTokenID(c)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	u, err := models.GetUserByID(user_id)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "success", "data": u})
}

type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {

	var input LoginInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	u := models.User{}

	u.Username = input.Username
	u.Password = input.Password

	token, err := models.LoginCheck(u.Username, u.Password)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username or password is incorrect."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})

}

type RegisterInput struct {
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
	FirstName       string `json:"firstName" binding:"required"`
	LastName        string `json:"lastName" binding:"required"`
}

func isPasswordValid(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSymbol
}

func Register(c *gin.Context) {

	var input RegisterInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !isPasswordValid(input.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter a valid password"})
		return
	}

	if input.Password != input.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter same Passwords"})
		return
	}

	u := models.User{}

	u.Username = input.Username
	u.Password = input.Password
	u.FirstName = input.FirstName
	u.LastName = input.LastName

	_, err := u.SaveUser()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "registration success"})

}

// Function to generate a reset password token and send it to the user
func CheckUsername(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	u, err := models.GetUserByUsername(input.Username)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username not found"})
		return
	}

	token, err := utils.GenerateTokenForResetPassword(u.ID) // Generate token for reset password
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// You can send the token to the user through email, SMS, or any other means
	// For simplicity, we'll just return it in the response
	c.JSON(http.StatusOK, gin.H{"message": "username found", "reset_token": token})
}

func UpdatePassword(c *gin.Context) {
	var input struct {
		Password        string `json:"password" binding:"required"`
		ConfirmPassword string `json:"confirmPassword" binding:"required"`
		Token           string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the reset password token and get the user ID
	userID, err := utils.ValidateResetPasswordTokenAndGetID(input.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	u, err := models.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	if !isPasswordValid(input.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter a valid password"})
		return
	}

	if input.Password != input.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter the same passwords"})
		return
	}

	u.Password = input.Password

	_, err = u.SaveUser()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password updated successfully"})
}
