package controllers

import (
	"context"
	"email-client/config"
	"email-client/models"
	"email-client/services"
	"fmt"
	"log"

	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// GET /check-patient?mobile=xxx&doctorId=yyy
func CheckPatientHandler(c *gin.Context) {
	mobile := c.Query("mobile")
	doctorId := c.Query("doctorId")

	if mobile == "" || doctorId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Mobile and DoctorId are required"})
		return
	}

	// Pass raw mobile directly
	patient, found := services.FetchPatientWithDoctorAccess(mobile, doctorId)
	if !found {
		c.JSON(http.StatusOK, gin.H{
			"exists":  false,
			"message": "No patient found for this mobile.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"exists":    true,
		"email":     patient["Email"],
		"dob":       patient["DOB"],
		"gender":    patient["Gender"],
		"name":      patient["Name"],
		"hasAccess": patient["hasAccess"],
	})
}

func SavePatientHandler(c *gin.Context) {
	var input struct {
		Name      string `json:"name"`
		Email     string `json:"email"`
		DOB       string `json:"dob"`
		Gender    string `json:"gender"`
		Mobile    string `json:"mobile"`
		DoctorId  string `json:"doctorId"`
		HasAccess string `json:"hasAccess"` // "Y" or "N"
	}

	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid input"})
		return
	}

	fromName := "Doctor"
	if val, ok := c.Get("fromName"); ok {
		fromName = val.(string)
	}

	// Validate email format
	emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	if input.Email != "" && !emailRegex.MatchString(input.Email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid email format. Please enter a valid email address.",
		})
		return
	}

	patientCol := config.GetPatientCollection()
	accessCol := config.GetDoctorPatientAccessCollection()

	// Raw mobile number as PatientId
	patientId := input.Mobile
	// ✅ Corrected domain load from config
	smtpConfig, err := config.LoadSMTPConfig()
	if err != nil {
		log.Printf("❌ Failed to load SMTP config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to load SMTP config"})
		return
	}
	domain := smtpConfig.Domain

	patientEmailId := fmt.Sprintf("%s%s", patientId, domain)

	var message string

	// Check if patient exists
	var existingPatient bson.M
	err = patientCol.FindOne(context.TODO(), bson.M{"Mobile": input.Mobile}).Decode(&existingPatient)
	if err != nil && err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Error querying patient collection"})
		return
	}

	if err == mongo.ErrNoDocuments {
		// New patient
		newPatient := bson.M{
			"Name":      input.Name,
			"Email":     input.Email,
			"DOB":       input.DOB,
			"Gender":    input.Gender,
			"Mobile":    input.Mobile,
			"CreatedAt": time.Now(),
		}

		_, err := patientCol.InsertOne(context.TODO(), newPatient)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to save patient"})
			return
		}

		_, err = accessCol.InsertOne(context.TODO(), bson.M{
			"DoctorId":  input.DoctorId,
			"PatientId": patientId,
			"HasAccess": input.HasAccess,
			"CreatedAt": time.Now(),
		})
		if err != nil {
			log.Printf("❌ Failed to create access record: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to create access record"})
			return
		}

		message = "Patient and access saved"
	} else {
		// Existing patient
		var existingAccess bson.M
		accessFilter := bson.M{"DoctorId": input.DoctorId, "PatientId": patientId}
		err = accessCol.FindOne(context.TODO(), accessFilter).Decode(&existingAccess)
		if err != nil && err != mongo.ErrNoDocuments {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Error querying access collection"})
			return
		}

		if err == mongo.ErrNoDocuments {
			_, err = accessCol.InsertOne(context.TODO(), bson.M{
				"DoctorId":  input.DoctorId,
				"PatientId": patientId,
				"HasAccess": input.HasAccess,
				"CreatedAt": time.Now(),
			})
			if err != nil {
				log.Printf("❌ Failed to create access record: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to create access record"})
				return
			}
			message = "Access created for existing patient"
		} else {
			currentAccess := existingAccess["HasAccess"]
			if currentAccess != input.HasAccess {
				_, err := accessCol.UpdateOne(context.TODO(), accessFilter, bson.M{
					"$set": bson.M{"HasAccess": input.HasAccess},
				})
				if err != nil {
					log.Printf("❌ Failed to update access record: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to update access"})
					return
				}
				message = "Access updated to " + input.HasAccess
			} else {
				message = "Patient and access already handled"
			}
		}
	}

	// Check if email communication exists (using email-like ID)
	exists, err := services.CheckEmailExists(input.DoctorId, patientEmailId)
	if err != nil {
		log.Printf("❌ Error checking email server: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Error checking email server"})
		return
	} else if !exists {
		err = services.SendEmailNewPatientRegistration(
			models.PatientDataModel{
				PatientName: input.Name,
				Email:       input.Email,
				Mobile:      input.Mobile,
				DOB:         input.DOB,
				Gender:      input.Gender,
				DoctorID:    input.DoctorId,
				DoctorName:  fromName,
			},
			patientEmailId,
			fromName,
		)

		if err != nil {
			log.Printf("❌ Failed to send email: %v", err)
		} else {
			log.Println("✅ Email sent successfully.")
		}
	} else {
		log.Println("ℹ️ Email communication exists between Doctor and Patient")
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": message})
}

// GET /check-access?doctorId=xyz&patientId=abc
func CheckDoctorAccess(c *gin.Context) {
	doctorId := c.Query("doctorId")
	patientId := c.Query("patientId")

	if doctorId == "" || patientId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing doctorId or patientId"})
		return
	}

	access, err := services.CheckAccessValue(doctorId, patientId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"hasAccess": access})

}

// HandleOtpSuccess handles logic after OTP is successfully verified

func UpdateAccess(c *gin.Context) {
	var requestBody struct {
		DoctorId  string `json:"doctorId" binding:"required"`  // Doctor's ID
		PatientId string `json:"patientId" binding:"required"` // Patient's ID
	}

	// Bind incoming JSON
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		log.Printf("❌ Invalid request format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request data. Please provide both doctorId and patientId.",
		})
		return
	}

	log.Printf("🔄 UpdateAccess called: doctorId = %s, patientId = %s", requestBody.DoctorId, requestBody.PatientId)

	// Call service layer to update access
	err := services.UpdateAccessIfExists(requestBody.DoctorId, requestBody.PatientId)
	if err != nil {
		log.Printf("❌ Failed to update/insert access: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to update or insert access.",
		})
		return
	}

	log.Printf("✅ Access successfully updated or inserted for doctorId = %s and patientId = %s", requestBody.DoctorId, requestBody.PatientId)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Access updated or inserted successfully.",
	})
}

// GetPatientByMobileHandler handles the HTTP request to fetch a patient by mobile number

// Fetch patient names and mobile numbers from PatientData collection

// Handler to fetch patients based on the logged-in email and return a unique list for the dropdown

// GetPatientsByLoggedInEmail fetches the list of patients based on the logged-in user's email
