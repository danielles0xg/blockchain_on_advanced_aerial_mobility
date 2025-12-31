// AAM Security Chaincode for Hyperledger Fabric
// Provides tamper-evident security event logging for Advanced Air Mobility

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// =============================================================================
// DATA STRUCTURES
// =============================================================================

// EventType represents the type of security event
type EventType uint8

const (
	GPS_SPOOF  EventType = 1
	DOS        EventType = 2
	MITM       EventType = 3
	REPLAY     EventType = 4
	GPS_JAM    EventType = 5
	EVIL_TWIN  EventType = 6
)

// SecurityEvent represents an AAM security event
type SecurityEvent struct {
	EventID        uint64    `json:"eventId"`
	BlockTimestamp int64     `json:"blockTimestamp"`
	TxID           string    `json:"txId"`
	EventTimestamp int64     `json:"eventTimestamp"`
	EventType      uint8     `json:"eventType"`
	Confidence     uint8     `json:"confidence"`
	VehicleID      string    `json:"vehicleId"`
	DataHash       string    `json:"dataHash"`
	SubmitTime     int64     `json:"submitTime,omitempty"` // Client submission time for metrics
}

// EventBatch represents a batch of security events
type EventBatch struct {
	BatchID        uint64           `json:"batchId"`
	BlockTimestamp int64            `json:"blockTimestamp"`
	TxID           string           `json:"txId"`
	EventCount     int              `json:"eventCount"`
	Events         []SecurityEvent  `json:"events"`
}

// Counter tracks the total number of events
type Counter struct {
	Count uint64 `json:"count"`
}

// =============================================================================
// SMART CONTRACT
// =============================================================================

// AAMSecurityContract provides functions for managing security events
type AAMSecurityContract struct {
	contractapi.Contract
}

// InitLedger initializes the ledger with counter
func (c *AAMSecurityContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	counter := Counter{Count: 0}
	counterJSON, err := json.Marshal(counter)
	if err != nil {
		return fmt.Errorf("failed to marshal counter: %v", err)
	}

	err = ctx.GetStub().PutState("eventCounter", counterJSON)
	if err != nil {
		return fmt.Errorf("failed to initialize counter: %v", err)
	}

	return nil
}

// LogSecurityEvent logs a new security event to the ledger
func (c *AAMSecurityContract) LogSecurityEvent(
	ctx contractapi.TransactionContextInterface,
	eventTimestamp int64,
	eventType uint8,
	confidence uint8,
	vehicleID string,
	dataHash string,
	submitTime int64,
) (*SecurityEvent, error) {

	// Validate inputs
	if eventType < 1 || eventType > 6 {
		return nil, fmt.Errorf("invalid event type: %d (must be 1-6)", eventType)
	}
	if confidence > 100 {
		return nil, fmt.Errorf("invalid confidence: %d (must be 0-100)", confidence)
	}

	// Get and increment counter
	counter, err := c.getCounter(ctx)
	if err != nil {
		return nil, err
	}

	eventID := counter.Count

	// Create event
	event := SecurityEvent{
		EventID:        eventID,
		BlockTimestamp: time.Now().Unix(),
		TxID:           ctx.GetStub().GetTxID(),
		EventTimestamp: eventTimestamp,
		EventType:      eventType,
		Confidence:     confidence,
		VehicleID:      vehicleID,
		DataHash:       dataHash,
		SubmitTime:     submitTime,
	}

	// Store event
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %v", err)
	}

	eventKey := fmt.Sprintf("EVENT_%d", eventID)
	err = ctx.GetStub().PutState(eventKey, eventJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to store event: %v", err)
	}

	// Update counter
	counter.Count++
	err = c.updateCounter(ctx, counter)
	if err != nil {
		return nil, err
	}

	// Emit event for client notification
	eventPayload, _ := json.Marshal(map[string]interface{}{
		"eventId":   eventID,
		"eventType": eventType,
		"txId":      event.TxID,
	})
	ctx.GetStub().SetEvent("SecurityEventLogged", eventPayload)

	return &event, nil
}

// LogBatchEvents logs multiple security events in a single transaction
func (c *AAMSecurityContract) LogBatchEvents(
	ctx contractapi.TransactionContextInterface,
	eventsJSON string,
) (*EventBatch, error) {

	var inputs []struct {
		EventTimestamp int64  `json:"eventTimestamp"`
		EventType      uint8  `json:"eventType"`
		Confidence     uint8  `json:"confidence"`
		VehicleID      string `json:"vehicleId"`
		DataHash       string `json:"dataHash"`
		SubmitTime     int64  `json:"submitTime"`
	}

	err := json.Unmarshal([]byte(eventsJSON), &inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse events JSON: %v", err)
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("batch cannot be empty")
	}
	if len(inputs) > 50 {
		return nil, fmt.Errorf("batch too large: max 50 events")
	}

	// Get counter
	counter, err := c.getCounter(ctx)
	if err != nil {
		return nil, err
	}

	batchID := counter.Count
	blockTimestamp := time.Now().Unix()
	txID := ctx.GetStub().GetTxID()

	events := make([]SecurityEvent, len(inputs))

	for i, input := range inputs {
		// Validate
		if input.EventType < 1 || input.EventType > 6 {
			return nil, fmt.Errorf("invalid event type at index %d: %d", i, input.EventType)
		}
		if input.Confidence > 100 {
			return nil, fmt.Errorf("invalid confidence at index %d: %d", i, input.Confidence)
		}

		eventID := counter.Count + uint64(i)

		events[i] = SecurityEvent{
			EventID:        eventID,
			BlockTimestamp: blockTimestamp,
			TxID:           txID,
			EventTimestamp: input.EventTimestamp,
			EventType:      input.EventType,
			Confidence:     input.Confidence,
			VehicleID:      input.VehicleID,
			DataHash:       input.DataHash,
			SubmitTime:     input.SubmitTime,
		}

		// Store individual event
		eventJSON, err := json.Marshal(events[i])
		if err != nil {
			return nil, fmt.Errorf("failed to marshal event %d: %v", i, err)
		}

		eventKey := fmt.Sprintf("EVENT_%d", eventID)
		err = ctx.GetStub().PutState(eventKey, eventJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to store event %d: %v", i, err)
		}
	}

	// Create batch record
	batch := EventBatch{
		BatchID:        batchID,
		BlockTimestamp: blockTimestamp,
		TxID:           txID,
		EventCount:     len(events),
		Events:         events,
	}

	batchJSON, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch: %v", err)
	}

	batchKey := fmt.Sprintf("BATCH_%d", batchID)
	err = ctx.GetStub().PutState(batchKey, batchJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to store batch: %v", err)
	}

	// Update counter
	counter.Count += uint64(len(events))
	err = c.updateCounter(ctx, counter)
	if err != nil {
		return nil, err
	}

	// Emit batch event
	batchPayload, _ := json.Marshal(map[string]interface{}{
		"batchId":    batchID,
		"eventCount": len(events),
		"txId":       txID,
	})
	ctx.GetStub().SetEvent("BatchEventsLogged", batchPayload)

	return &batch, nil
}

// GetEvent retrieves a security event by ID
func (c *AAMSecurityContract) GetEvent(
	ctx contractapi.TransactionContextInterface,
	eventID uint64,
) (*SecurityEvent, error) {

	eventKey := fmt.Sprintf("EVENT_%d", eventID)
	eventJSON, err := ctx.GetStub().GetState(eventKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read event: %v", err)
	}
	if eventJSON == nil {
		return nil, fmt.Errorf("event %d does not exist", eventID)
	}

	var event SecurityEvent
	err = json.Unmarshal(eventJSON, &event)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %v", err)
	}

	return &event, nil
}

// GetEventsByVehicle retrieves all events for a specific vehicle
func (c *AAMSecurityContract) GetEventsByVehicle(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) ([]*SecurityEvent, error) {

	// Use rich query with CouchDB
	queryString := fmt.Sprintf(`{"selector":{"vehicleId":"%s"}}`, vehicleID)

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %v", err)
	}
	defer resultsIterator.Close()

	var events []*SecurityEvent
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var event SecurityEvent
		err = json.Unmarshal(queryResponse.Value, &event)
		if err != nil {
			return nil, err
		}
		events = append(events, &event)
	}

	return events, nil
}

// GetEventsByType retrieves all events of a specific type
func (c *AAMSecurityContract) GetEventsByType(
	ctx contractapi.TransactionContextInterface,
	eventType uint8,
) ([]*SecurityEvent, error) {

	queryString := fmt.Sprintf(`{"selector":{"eventType":%d}}`, eventType)

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %v", err)
	}
	defer resultsIterator.Close()

	var events []*SecurityEvent
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var event SecurityEvent
		err = json.Unmarshal(queryResponse.Value, &event)
		if err != nil {
			return nil, err
		}
		events = append(events, &event)
	}

	return events, nil
}

// GetEventCount returns the total number of events
func (c *AAMSecurityContract) GetEventCount(
	ctx contractapi.TransactionContextInterface,
) (uint64, error) {

	counter, err := c.getCounter(ctx)
	if err != nil {
		return 0, err
	}

	return counter.Count, nil
}

// GetEventRange retrieves events within a range of IDs
func (c *AAMSecurityContract) GetEventRange(
	ctx contractapi.TransactionContextInterface,
	startID uint64,
	endID uint64,
) ([]*SecurityEvent, error) {

	if endID < startID {
		return nil, fmt.Errorf("endID must be >= startID")
	}
	if endID-startID > 1000 {
		return nil, fmt.Errorf("range too large: max 1000 events")
	}

	var events []*SecurityEvent
	for id := startID; id <= endID; id++ {
		event, err := c.GetEvent(ctx, id)
		if err == nil {
			events = append(events, event)
		}
	}

	return events, nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func (c *AAMSecurityContract) getCounter(ctx contractapi.TransactionContextInterface) (*Counter, error) {
	counterJSON, err := ctx.GetStub().GetState("eventCounter")
	if err != nil {
		return nil, fmt.Errorf("failed to read counter: %v", err)
	}
	if counterJSON == nil {
		// Initialize counter if not exists
		return &Counter{Count: 0}, nil
	}

	var counter Counter
	err = json.Unmarshal(counterJSON, &counter)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal counter: %v", err)
	}

	return &counter, nil
}

func (c *AAMSecurityContract) updateCounter(ctx contractapi.TransactionContextInterface, counter *Counter) error {
	counterJSON, err := json.Marshal(counter)
	if err != nil {
		return fmt.Errorf("failed to marshal counter: %v", err)
	}

	return ctx.GetStub().PutState("eventCounter", counterJSON)
}

// =============================================================================
// MAIN
// =============================================================================

func main() {
	chaincode, err := contractapi.NewChaincode(&AAMSecurityContract{})
	if err != nil {
		fmt.Printf("Error creating AAM Security chaincode: %v", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting AAM Security chaincode: %v", err)
	}
}
