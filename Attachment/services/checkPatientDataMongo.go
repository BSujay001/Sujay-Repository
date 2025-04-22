package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"email-client/config"
	"email-client/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// GetPatientByMobile fetches patient data by mobile number

// GetPatientByMobile fetches patient data by mobile number

// GetEnrichedRecipients returns recipient list with name or fallback to mobile

// GetEnrichedRecipients returns a list of RecipientInfo with names fetched from MongoDB
func GetEnrichedRecipients(loggedInEmail string) ([]models.RecipientInfo, error) {
	// Fetch the raw list of unique recipient emails
	rawEmails, err := GetUniqueRecipients(loggedInEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch unique recipients: %w", err)
	}

	var enriched []models.RecipientInfo

	// Iterate through each email
	for _, email := range rawEmails {
		// Split the email at the '@' symbol to separate the mobile part
		parts := strings.Split(email, "@")

		// Ensure the split parts are valid
		if len(parts) < 2 {
			log.Printf("❌ Invalid email format: %s", email)
			continue
		}

		mobile := strings.TrimSpace(parts[0]) // Extract the mobile number (before '@')

		// Fetch patient details based on the mobile number
		patient, err := GetPatientByMobile(mobile)
		if err != nil || patient == nil || patient.PatientName == "" {
			// Fallback to mobile if no name is found
			log.Printf("⚠️ No name found for mobile %s, using fallback", mobile)
			enriched = append(enriched, models.RecipientInfo{
				EmailId: email,
				Name:    mobile, // fallback to mobile
			})
		} else {
			// Use the patient's name if found
			enriched = append(enriched, models.RecipientInfo{
				EmailId: email,
				Name:    patient.PatientName,
			})
		}
	}

	return enriched, nil
}

// Fetches patient details from MongoDB using just the mobile part of the email
// Fetches patient details from MongoDB using just the mobile part of the email
// GetPatientByMobile fetches patient details from MongoDB using the mobile number
func GetPatientByMobile(mobile string) (*models.PatientDataModel, error) {
	collection := config.GetPatientCollection()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"Mobile": mobile}

	var patient models.PatientDataModel
	err := collection.FindOne(ctx, filter).Decode(&patient)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("🔍 No patient found for mobile: %s", mobile)
			return nil, nil
		}
		log.Printf("❌ Error fetching patient for mobile %s: %v", mobile, err)
		return nil, err
	}

	// Log the patient name if successfully fetched
	log.Printf("✅ Patient found: %s (%s)", patient.PatientName, patient.Mobile)

	// Return the patient data
	return &patient, nil
}
