package initializers

import "github.com/chtiwa/go_jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
