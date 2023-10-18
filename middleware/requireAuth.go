package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/chtiwa/go_jwt/initializers"
	"github.com/chtiwa/go_jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func RequireAuth(c *gin.Context) {
	// sample token string taken from the New example
	tokenString, err := c.Cookie("refresh_token")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "refresh_token was not found!",
		})
	}
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// check if the token is expired
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			fmt.Println(float64(time.Now().Unix()))
			fmt.Println(claims["sub"].(float64))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Token was expired!",
			})
		}
		// a variable to store the found user
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "User was not found!",
			})
		}

		// attach the user to the request
		c.Set("user", user)

		c.Next()
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "Token is not valid!",
		})
	}
}
