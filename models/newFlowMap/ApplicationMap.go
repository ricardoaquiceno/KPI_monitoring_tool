package newFlowMap

import (
	"container/list"
	"errors"
	"fmt"
	"gopacket_analysis/models"
	"gopacket_analysis/models/errorRateMap"
	"gopacket_analysis/models/passiveLatencyMap"
	"gopacket_analysis/protocols"
	"time"
)

// ApplicationMapElement contains the data of the ApplicationMap.
// This includes identifying data for the Application such as Source and Destination Ports and potential Traffic (HTTP,
// QUIC, DNS, ...) and Application types (Audio, Video, Web Browsing, ...) but also performance metrics such as
// throughput, latency, ...
type ApplicationMapElement struct {
	// Mandatory Data, even though PotentialTrafficMap could stay empty
	SrcPort                  uint16
	DstPort                  uint16
	PotentialTrafficType     []string // Might be best to leave TCP/UDP just at top and have stuff like QUIC/HTTP here
	PotentialApplicationType []string // Like Audio, Video, ...
	LastPacketTime           time.Time
	Measurements             Measurements
	listPointer              *list.Element

	// Optional Data, can be nil if not used, only accessible privately
	passiveLatencyMap *passiveLatencyMap.PassiveLatencyMap
	errorRateMap      *errorRateMap.ErrorRateMap
	quicFlow          *protocols.QuicFlow
}

// Measurements is a struct that contains the actual measurement statistics of an ApplicationMapElement.
// This is the already aggregated data.
type Measurements struct {
	PacketsIn  int
	PacketsOut int

	SizeBytesIn  uint64
	SizeBytesOut uint64

	// ToDo: Decide on good approach for optional data
	//  If for example no RTT measurement has been done, the RTTPacketsPLM will be 0 meaning we can ignore it?
	//  Or would we still better need to differentiate between 0 and nil packets, and use a pointer to the ints?
	//  Or better yet create structs for each optional measurement type so we can nil these but don't have to do
	//  pointer operations for each optional int value.
	RttPacketsPLM int
	RttSumPLM     time.Duration

	ErmPacketsCount int
	ErmDuplicates   int

	QuicPackets int
}

// ApplicationMapOptionalParameters are optional Parameters that are needed for adding optional info to the
// ApplicationMapElement such as entries to the passiveLatencyMap (by use of their Key and Timestamp) or the
// errorRateMap (by use of their FlowID, PacketID and RecordData)
type ApplicationMapOptionalParameters struct {
	PassiveLatencyMapKey       *passiveLatencyMap.PassiveLatencyPacketID
	PassiveLatencyMapTimestamp *time.Time

	ErrorRateFlowID     *models.FlowID
	ErrorRatePacketID   *errorRateMap.ErrorRatePacketID
	ErrorRateRecordData *errorRateMap.RecordData
}

// ApplicationMapID consists of the TransportFlowHash, which is just the Layer2.TransportFlow().FastHash() consisting of
// a hash of the source and destination Port, as well as the Transport Protocol, as you could theoretically have a TCP
// and UDP connection between the same Ports. There is a chance for accidental grouping of distinct flows if for example
// we have one connection from A:1234 to B:80 and also one from B:1234 to A:80 but the chance is incredibly low as the
// OS should avoid these situations automatically
type ApplicationMapID struct {
	TransportFlowHash uint64
	TransportProtocol string // Might be good to use fixed definitions (enum) instead of free string
}

// ApplicationMap is the main structure that contains the Applications map with the actual data, as well as the queue
// and maxSize wich are required for maintaining the ApplicationMap
type ApplicationMap struct {
	// Flows are based on destination and source Port
	Applications map[ApplicationMapID]*ApplicationMapElement

	// The queue is actually an array that emulates a queue and is used to keep track of the age/order of the packets
	queue *list.List
	// Helper variables of the queue
	maxSize int
}

// NewApplicationMap is a helper function for creating a new ApplicationMap
func NewApplicationMap(size int) *ApplicationMap {
	return &ApplicationMap{
		Applications: make(map[ApplicationMapID]*ApplicationMapElement),
		queue:        list.New(),
		maxSize:      size,
	}
}

// Contains returns true if the ApplicationMap contains the Application
func (m *ApplicationMap) Contains(key ApplicationMapID) bool {
	_, ok := m.Applications[key]
	return ok
}

// Len returns the length of the ApplicationMap.
func (m *ApplicationMap) Len() int {
	return len(m.Applications)
}

// Add new data to the ApplicationMap, using the ApplicationMapID as the key and additional info such as the Ports,
// Potential Traffic and Application Types (if none classified, just send empty slice), lastPacketTime, Measurements and
// optional parameters
// If the ApplicationMapID does not yet exist, create a new ApplicationMapElement with the data provided, otherwise just
// update the existing one with the data provided.
// If we are at max length the function will automatically delete the oldest ApplicationMapElement first.
func (m *ApplicationMap) Add(key ApplicationMapID, basicApplicationElement *ApplicationMapElement,
	optionalParameters ApplicationMapOptionalParameters) (error, *ApplicationMapElement) {
	// ToDo: actually change signature to only key and basicApplicationElement of type ApplicationMapElement
	//  just like I do in FlowMap.AddPacket
	actualElement, elementExists := m.Applications[key]
	var elementToEdit *ApplicationMapElement
	if !elementExists {
		// Need to add a new ApplicationMapElement

		// If the queue is full, remove the oldest entry
		if len(m.Applications) == m.maxSize {
			err := m.RemoveOldest()
			if err != nil {
				// FixMe: Add Error
				if err.Error() == AlreadyDeletedErr {
					fmt.Println("Got an AlreadyDeletedErr while removing the oldest packet in order to add a new one")
					return nil, nil
				}
			}
			if len(m.Applications) == m.maxSize {
				fmt.Println("Shit")
				return nil, nil
			}
		}
		// Finally add the current entry
		// Add Key to the back of the Queue
		queuePointer := m.queue.PushBack(key)
		elementToEdit = &ApplicationMapElement{}
		elementToEdit.SrcPort = basicApplicationElement.SrcPort
		elementToEdit.DstPort = basicApplicationElement.DstPort
		elementToEdit.PotentialTrafficType = basicApplicationElement.PotentialTrafficType
		elementToEdit.PotentialApplicationType = basicApplicationElement.PotentialApplicationType
		elementToEdit.LastPacketTime = basicApplicationElement.LastPacketTime
		elementToEdit.listPointer = queuePointer

		elementToEdit.Measurements = basicApplicationElement.Measurements

	} else {
		// Need to check and update existing ApplicationMapElement

		// Measurement Info
		elementToEdit = actualElement

		elementToEdit.Measurements.PacketsIn += basicApplicationElement.Measurements.PacketsIn
		elementToEdit.Measurements.PacketsOut += basicApplicationElement.Measurements.PacketsOut

		// ToDo: check Ports, actually might redo ports as source and destination will switch whenever traffic flows in
		//  the different direction.
		elementToEdit.Measurements.SizeBytesIn += basicApplicationElement.Measurements.SizeBytesIn
		elementToEdit.Measurements.SizeBytesOut += basicApplicationElement.Measurements.SizeBytesOut

		elementToEdit.Measurements.QuicPackets += basicApplicationElement.Measurements.QuicPackets

		// Main Info
		for _, trafficType := range basicApplicationElement.PotentialTrafficType {
			elementToEdit.PotentialTrafficType = addPotentialType(elementToEdit.PotentialTrafficType, trafficType)
		}
		for _, applicationType := range basicApplicationElement.PotentialApplicationType {
			elementToEdit.PotentialApplicationType = addPotentialType(elementToEdit.PotentialApplicationType, applicationType)
		}
		elementToEdit.LastPacketTime = basicApplicationElement.LastPacketTime
	}

	// ToDo: Actually handle measurements

	// Todo: Actually handle optionalParameters

	// Finally add the element to the map and
	m.Applications[key] = elementToEdit
	return nil, elementToEdit
}

func addPotentialType(potentialTypeList []string, potentialType string) []string {
	for _, _potentialType := range potentialTypeList {
		if _potentialType == potentialType {
			return potentialTypeList
		}
	}
	return append(potentialTypeList, potentialType)
}

// RemoveOldest removes the oldest Packet from the ApplicationMap
func (m *ApplicationMap) RemoveOldest() error {
	// Delete the oldest element and get its value casted to an ApplicationMapID
	key := m.queue.Remove(m.queue.Front()).(ApplicationMapID)

	mapLen1 := m.Len()

	// Actual Deletion of element in map
	delete(m.Applications, key)

	mapLen2 := m.Len()
	queueLen := m.queue.Len()

	if mapLen1 == mapLen2 || mapLen2 != queueLen {
		return errors.New(DeleteOldestErr)
	}
	return nil
}

// Remove the specified Packet from the PassiveLatencyMap
// Can throw following Errors: "AlreadyDeletedErr", "DeleteOldestErr"
func (m *ApplicationMap) Remove(key ApplicationMapID) error {
	if !m.Contains(key) {
		// Nothing to delete, done
		return errors.New(AlreadyDeletedErr)
	} else {
		mapLen1 := m.Len()

		record := m.Applications[key]

		// Remove packet from Queue
		m.queue.Remove(record.listPointer)

		// Delete packet from map
		delete(m.Applications, key)

		mapLen2 := m.Len()
		queueLen := m.queue.Len()
		if mapLen1 == mapLen2 || mapLen2 != queueLen {
			return errors.New(DeleteOldestErr)
		}
		return nil
	}
}

// ClearOld will clear all records in the PLM that are older than the duration passed as an argument.
// This will garbage collect packets deemed irrelevant as the latency might be too high.
// Still up for debate if I need this function here, or not.
func (m *ApplicationMap) ClearOld(maxAge time.Duration) {
	for packetID, app := range m.Applications {
		if time.Since(app.LastPacketTime) > maxAge {
			err := m.Remove(packetID)
			if err != nil {
			}
		}
	}
}
