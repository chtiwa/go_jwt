package initializers

import (
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// globale variable
var DB *gorm.DB

func ConnectToDB() {
	var err error
	dsn := os.Getenv("DB_URL_INTERNAL")
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Error while connecting to the database!")
	}
}
