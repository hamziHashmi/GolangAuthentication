package main

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/hamziHashmi/GolangAuthentication/controller"
	"github.com/hamziHashmi/GolangAuthentication/middlewares"
	"github.com/hamziHashmi/GolangAuthentication/models"
)

func main() {
	models.ConnectDataBase()

	r := gin.Default()

	public := r.Group("/api")
	public.POST("/register", controllers.Register)
	public.POST("/login", controllers.Login)
	public.POST("/check-username", controllers.CheckUsername)   // New endpoint to check if username exists
	public.POST("/update-password", controllers.UpdatePassword) // New endpoint to update the password

	protected := r.Group("/api/admin")
	protected.Use(middlewares.JwtAuthMiddleware())
	protected.GET("/user", controllers.CurrentUser)

	r.Run(":8080")
}
