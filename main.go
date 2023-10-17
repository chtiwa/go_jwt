package main

import (
	"github.com/chtiwa/go_jwt/controllers"
	"github.com/chtiwa/go_jwt/initializers"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.POST("/validate", controllers.Validate)

	r.Run()
}
