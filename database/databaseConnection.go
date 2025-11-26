/*
Author: Ayush Poudel
--------------------
Reference: https://www.mongodb.com/docs/drivers/go/current/get-started/#:~:text=in%20MongoDB%20Atlas.-,package%20main,%7D,-4
This file is responsible for creating a connection with MongoDB database
For local testing run :-	 docker run -d --name mongo -p 27017:27017 mongo:latest && export MONGODB_URL=mongodb://localhost:27017


How to connect to MongoDB or any DB?

1. Go to https://www.mongodb.com/docs/drivers/go/current/get-started/
2. We need to do following things
	a. Load DB Config from Environment
	b. Create Client
	c. Connect to DB using client with timeout
	d. See if connection is successful (Ping)
	e. Open a collection for use across the app
*/

package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func loadEnvConfig() (uri string, dbName string) {
	uri = os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatal("MONGODB_URI not set in environment")
	}
	dbName = os.Getenv("DB_NAME")
	if dbName == "" {
		log.Fatal("DB_NAME not set in environment")
	}
	return
}

func createClient() *mongo.Client {
	uri, _ := loadEnvConfig()
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.NewClient(clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func connectClient(client *mongo.Client) *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		log.Fatal("MongoDB connection failed ", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB unreachable ", err)
	}
	fmt.Println("Connected to MongoDB")
	return client
}

func DisconnectDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Client.Disconnect(ctx); err != nil {
		log.Println("Error disconnecting MongoDB:", err)
	} else {
		fmt.Println("MongoDB disconnected")
	}
}

var Client *mongo.Client = connectClient(createClient())

func OpenCollection(collectionName string) *mongo.Collection {
	_, dbName := loadEnvConfig()
	collection := Client.Database(dbName).Collection(collectionName)
	return collection
}
