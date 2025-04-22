package services

import (
	"context"
	"email-client/config"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// FetchPatientWithDoctorAccess fetches patient info and access flag
func FetchPatientWithDoctorAccess(mobile string, doctorId string) (map[string]interface{}, bool) {
	patientCol := config.GetPatientCollection()
	accessCol := config.GetDatabase().Collection("RecordAccessRights")

	fmt.Println("🔍 Checking patient for mobile:", mobile)
	fmt.Println("🔍 Checking access for doctorId:", doctorId)

	// Step 1: Fetch patient using raw mobile number
	var patient map[string]interface{}
	err := patientCol.FindOne(context.TODO(), bson.M{"Mobile": mobile}).Decode(&patient)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			fmt.Println("❌ No patient found for mobile:", mobile)
			return nil, false
		}
		fmt.Println("❌ Error fetching patient:", err)
		return nil, false
	}

	// Step 2: Fetch access flag using mobile as PatientId (same value)
	var access struct {
		HasAccess string `bson:"HasAccess"`
	}
	err = accessCol.FindOne(context.TODO(), bson.M{
		"DoctorId":  doctorId,
		"PatientId": mobile, // ✅ PatientId is now just mobile
	}).Decode(&access)

	if err == mongo.ErrNoDocuments {
		fmt.Println("ℹ️ No access record found. Setting hasAccess to false.")
		patient["hasAccess"] = false
	} else if err != nil {
		fmt.Println("❌ Error fetching access:", err)
		patient["hasAccess"] = false
	} else {
		patient["hasAccess"] = (access.HasAccess == "Y")
	}

	return patient, true
}

// controller or services

func CheckAccessValue(doctorId, patientId string) (string, error) {
	// Get the DoctorPatientAccess collection
	collection := config.GetDoctorPatientAccessCollection()

	var result struct {
		HasAccess string `bson:"HasAccess"` // MongoDB field name
	}

	// Query the collection for matching DoctorId and PatientId
	err := collection.FindOne(context.TODO(), bson.M{
		"DoctorId":  doctorId, // Ensure field name matches the DB schema
		"PatientId": patientId,
	}).Decode(&result)

	// Handle the error if no document is found
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Return custom value when no record is found
			return "NOT_FOUND", nil
		}
		// Return error if there’s a different issue (e.g., connection issues)
		return "", err
	}

	// Return the access value if the document is found
	return result.HasAccess, nil
}

func UpdateAccessIfExists(doctorId, patientId string) error {
	collection := config.GetDoctorPatientAccessCollection()

	// No domain transformation for patientId
	// Use patientId directly without modifying it
	filter := bson.M{
		"DoctorId":  doctorId,
		"PatientId": patientId, // Use patientId directly
		"HasAccess": "N",
	}

	// Update to set HasAccess to "Y"
	update := bson.M{
		"$set": bson.M{"HasAccess": "Y"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to update the existing record
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Printf("❌ Error updating access: %v", err)
		return err
	}

	// If a record was updated, log the success
	if result.ModifiedCount > 0 {
		log.Println("✅ Access updated to Y for existing record.")
		return nil
	}

	// If no record was updated, insert a new one
	log.Println("ℹ️ No matching record found or no update needed, creating new record.")

	newRecord := bson.M{
		"DoctorId":  doctorId,
		"PatientId": patientId, // Use patientId directly
		"HasAccess": "Y",       // New record with HasAccess = Y
	}

	_, err = collection.InsertOne(ctx, newRecord)
	if err != nil {
		log.Printf("❌ Error inserting new record: %v", err)
		return err
	}

	log.Println("✅ New access record created with HasAccess = Y.")
	return nil
}
