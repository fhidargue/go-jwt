package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Todo struct {
	Text string
	Done bool
}

var todos []Todo
var currentUser string

// Secret Key
var secretKey = []byte("FFQHVsvQOUCN0qhB4sTq2RX0atIsMfCQ")

func getRole(username string) string {
	if username == "senior" {
		return "senior"
	}
	return "employee"
}

func createToken(username string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,
		"iss": getRole(username),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	fmt.Printf("Token claims added: %+v\n", claims)

	tokenString, err := claims.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func toggleIndex(index string){
	i, _ := strconv.Atoi(index)
	if i >= 0 && i < len(todos) {
		todos[i].Done = !todos[i].Done
	}
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}	

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func authenticatedMiddleware(c *gin.Context) {
	tokenString, err := c.Cookie("token")
	if err != nil {
		fmt.Println("Cookie token not found")
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
		return
	}

	token, err := verifyToken(tokenString)
	if err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
		return
	}
	
	fmt.Printf("Token verified successfully. ClaimsL %+v\n", token.Claims)
	c.Next()
}

func main() {
	router := gin.Default()

	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Todos": todos,
			"LoggedIn": currentUser != "",
			"Username": currentUser,
			"Role": getRole(currentUser),
		})
	})

	router.POST("/add", authenticatedMiddleware, func(c *gin.Context){
		text := c.PostForm("todo")
		todo := Todo{Text: text, Done: false}
		todos = append(todos, todo)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.POST("/toggle", authenticatedMiddleware, func(c *gin.Context){
		index := c.PostForm("index")
		toggleIndex(index)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.POST("/login", func(c *gin.Context){
		username := c.PostForm("username")
		password := c.PostForm("password")

		if (username == "employee" && password == "password") || (username == "senior" && password == "password") {
			tokenString, err := createToken(username)
			if err != nil {
				c.String(http.StatusInternalServerError, "Error creating the token")
				return
			}

			currentUser = username
			fmt.Printf("Token created: %s\n", tokenString)
			c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)
			c.Redirect(http.StatusSeeOther, "/")
		} else {
			c.String(http.StatusUnauthorized, "Invalid credentials")
		}
	})

	router.GET("/logout", func(c *gin.Context) {
		currentUser = ""
		c.SetCookie("token", "", -1, "/", "localhost", false, true)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.Run(":8080")
}