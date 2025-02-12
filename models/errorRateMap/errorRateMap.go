// Package errorRateMap should implement a structure similar to the passiveLatencyMap, though more oriented towards
// capturing data related to measuring the retransmit rate (packet loss) and other metrics such as duplicated
// acknowledgements or out of order transmissions
package errorRateMap

import (
	"container/list"
	"errors"
	"fmt"
	"gopacket_analysis/models"
	"time"
)

const (
	DupErr            = "duplicate packet"
	AlreadyDeletedErr = "packet already deleted"
	NotFoundErr       = "packet not found"
	DeleteOldestErr   = "packet delete oldest has error"
	ConnectionClose   = "received connection close command"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FlowErrorRateMap as the main structure that orders the packets by their flow

// FlowErrorRateMap is a map that contains all current flows and their ErrorRateMap in the flowMap
type FlowErrorRateMap struct {
	FlowMap map[models.FlowID]*ErrorRateMap
}

// NewFlowErrorRateMap is a helper function for creating a new FlowErrorRateMap
func NewFlowErrorRateMap() *FlowErrorRateMap {
	return &FlowErrorRateMap{
		FlowMap: make(map[models.FlowID]*ErrorRateMap),
	}
}

// Add a Packet Record to the ErrorRateMap of the flow using the packetID as the identifier of the packet.
// If the flow is new, create a new ErrorRateMap, else add the packet to it.
// If the packet already exists,
func (m *FlowErrorRateMap) Add(flow models.FlowID, packetID ErrorRatePacketID, packetRecord *RecordData) error {
	if _, ok := m.FlowMap[flow]; !ok {
		// New Flow, create it in the flow map
		m.FlowMap[flow] = NewErrorRateMap(100)
	}
	if packetRecord.packetType == models.PacketTypeFin || packetRecord.packetType == models.PacketTypeRst {
		// We can close the connection and delete the flow
		// TestMe: I think this does not work
		// ToDo: maybe implement state control for a flow so that we can set a state like:
		// 	syn, synack, ack, normal, fin1, finack1, fin2, finack2
		delete(m.FlowMap, flow)
		return errors.New(ConnectionClose)
	}

	err := m.FlowMap[flow].Add(packetID, packetRecord)
	if err != nil {
		if err.Error() != DupErr {
			fmt.Println(err)
		}
		return err
	} else {
		// TestMe Check if out of order detection is correct
		// Do the out-of-order test here
		predecessorID, predecessorErr := m.FlowMap[flow].GetPredecessor(packetID)
		if predecessorErr != nil {
			// Somehow handle the errors
		} else {
			// Here we should actually test if the predecessor is the actual tcp predecessor by using ack and seq id as
			// well as the data size
			predecessorData := m.FlowMap[flow].PacketMap[predecessorID]
			if predecessorData.data.outgoingDirection == packetRecord.outgoingDirection {
				// Same Direction

				excpectedSeq := predecessorData.data.sequenceNumber + predecessorData.data.payloadSize
				excpectedAck := predecessorData.data.acknowledgementNumber
				if excpectedAck != packetRecord.acknowledgementNumber {
					//fmt.Println("Same Direction had different Ack Num")
				}

				if excpectedSeq < packetRecord.sequenceNumber {
					//fmt.Println("Same Direction had different Sequence Num: Looks to be newer than expected")
				} else if excpectedSeq > packetRecord.sequenceNumber {
					//fmt.Println("Same Direction had different Sequence Num: Looks to be older than last packet")
				} else {
					// All fine
				}
			} else {
				// Different Direction
				excpectedSeq := predecessorData.data.acknowledgementNumber
				excpectedAck := predecessorData.data.sequenceNumber + predecessorData.data.payloadSize
				if excpectedSeq != packetRecord.sequenceNumber {
					//fmt.Println("Different Direction had different Seq Num")
				}
				if excpectedAck < packetRecord.acknowledgementNumber {
					//fmt.Println("Different Direction had different Different Num: Looks to be newer than expected")
				} else if excpectedAck > packetRecord.acknowledgementNumber {
					//fmt.Println("Different Direction had different Different Num: Looks to be older than last packet")
				} else {
					// All fine
				}
			}
		}
	}
	return nil
}

func (m *FlowErrorRateMap) GetFlowCount() int {
	return len(m.FlowMap)
}

func (m *FlowErrorRateMap) GetFlow(flowID models.FlowID) (*ErrorRateMap, error) {
	if _, ok := m.FlowMap[flowID]; !ok {
		return nil, errors.New(NotFoundErr)
	}
	return m.FlowMap[flowID], nil
}

func (m *FlowErrorRateMap) GetPacket(flowID models.FlowID, packetID ErrorRatePacketID) (*RecordData, error) {
	if flow, okFlow := m.FlowMap[flowID]; okFlow {
		if packet, okPacket := flow.PacketMap[packetID]; okPacket {
			return packet.data, nil
		}
	}
	return nil, errors.New(NotFoundErr)

}

func (m *FlowErrorRateMap) DeleteInactiveFlows(timeout time.Duration) int {
	deleteCount := 0
	for flowID, entry := range m.FlowMap {
		if time.Since(entry.lastPacketTime) > timeout {
			delete(m.FlowMap, flowID)
			deleteCount++
		}
	}
	return deleteCount
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Actual ErrorRateMap that contains the packets

// ErrorRatePacketID uniquely identifies a packet
type ErrorRatePacketID struct {
	AckID  uint32
	SeqID  uint32
	DirTyp string
}

// Record that contains the pointer of the map entry to the queue and the actual packet data
type Record struct {
	data        *RecordData
	listPointer *list.Element
}

// RecordData contains the actual data of the record
// ToDo: See if this is enough or I need more
// FixMe: Might not need Ack and Seq in here as they already are the key
type RecordData struct {
	timestamp             time.Time
	outgoingDirection     bool
	sequenceNumber        uint32
	acknowledgementNumber uint32
	payloadSize           uint32
	packetType            int
}

func NewRecordData(_timestamp time.Time, _outgoing bool, _seqNum uint32, _ackNum uint32, _payloadSize uint32, _packetType int) *RecordData {
	return &RecordData{timestamp: _timestamp, outgoingDirection: _outgoing, sequenceNumber: _seqNum,
		acknowledgementNumber: _ackNum, payloadSize: _payloadSize, packetType: _packetType}
}

// ErrorRateMap contains the datastructure for the packets of the flow
type ErrorRateMap struct {
	// PacketMap Contains the relevant information of the packet (like a timestamp) and can be accessed using the PassiveLatencyPacketID
	PacketMap map[ErrorRatePacketID]Record

	// The queue is actually an array that emulates a queue and is used to keep track of the age/order of the packets
	queue *list.List
	// Helper variables of the queue
	maxSize int

	// Timestamp when last packet was received (to detect unused connections when last PacketTime was too long ago)
	lastPacketTime time.Time
}

// NewErrorRateMap is a helper function for creating a new ErrorRateMap
func NewErrorRateMap(size int) *ErrorRateMap {
	return &ErrorRateMap{
		PacketMap: make(map[ErrorRatePacketID]Record),
		queue:     list.New(),
		maxSize:   size,
	}
}

// Contains returns true if the PassiveLatencyMap contains the packet
func (m *ErrorRateMap) Contains(key ErrorRatePacketID) bool {
	_, ok := m.PacketMap[key]
	return ok
}

// Len returns the length of the PacketMap. Note that this may differ from the size of the queue if the queue is at max
// length, but we remove a Packet that was already acked.
func (m *ErrorRateMap) Len() int {
	return len(m.PacketMap)
}

func (m *ErrorRateMap) Add(key ErrorRatePacketID, packetData *RecordData) error {

	// Packet already in Map, so this packet is a duplicate
	if m.Contains(key) {
		// ToDo: Add a test to see if this is duplicate ack or a fast/slow retransmit
		original := m.PacketMap[key]
		if original.data.outgoingDirection == packetData.outgoingDirection {
			if original.data.packetType != packetData.packetType {
				println(original.data.packetType, packetData.packetType)
			}

		}
		return errors.New(DupErr)
	}

	// If the queue is full, remove the oldest entry
	if len(m.PacketMap) == m.maxSize {
		err := m.RemoveOldest()
		if err != nil {
			if err.Error() == AlreadyDeletedErr {
				fmt.Println("Got an AlreadyDeletedErr while removing the oldest packet in order to add a new one")
				return nil
			}
		}
		if len(m.PacketMap) == m.maxSize {
			fmt.Println("Shit")
			return nil
		}
	}

	// Finally add the current entry
	// Add Key to the back of the Queue
	queuePointer := m.queue.PushBack(key)

	// Create record for map
	record := Record{
		data:        packetData,
		listPointer: queuePointer,
	}
	m.PacketMap[key] = record
	m.lastPacketTime = packetData.timestamp
	return nil
}

// RemoveOldest removes the oldest Packet from the PassiveLatencyMap
func (m *ErrorRateMap) RemoveOldest() error {
	// Delete the oldest element and get its value casted to a Packet ID
	key := m.queue.Remove(m.queue.Front()).(ErrorRatePacketID)

	mapLen1 := m.Len()

	// Actual Deletion of element in map
	delete(m.PacketMap, key)

	mapLen2 := m.Len()
	queueLen := m.queue.Len()

	if mapLen1 == mapLen2 || mapLen2 != queueLen {
		return errors.New(DeleteOldestErr)
	}
	return nil
}

// Remove the specified Packet from the PassiveLatencyMap
func (m *ErrorRateMap) Remove(key ErrorRatePacketID) error {
	if !m.Contains(key) {
		// Nothing to delete, done
		return errors.New(AlreadyDeletedErr)
	} else {
		mapLen1 := m.Len()

		record := m.PacketMap[key]

		// Remove packet from Queue
		m.queue.Remove(record.listPointer)

		// Delete packet from map
		delete(m.PacketMap, key)

		mapLen2 := m.Len()
		queueLen := m.queue.Len()
		if mapLen1 == mapLen2 || mapLen2 != queueLen {
			return errors.New(DeleteOldestErr)
		}
		return nil
	}
}

func (m *ErrorRateMap) GetPredecessor(key ErrorRatePacketID) (ErrorRatePacketID, error) {
	mapLen := m.Len()
	if mapLen == 0 {
		// Return some error that this should not be possible
		return ErrorRatePacketID{}, errors.New(NotFoundErr)
	} else if mapLen == 1 {
		// This packet was the only one here
		return ErrorRatePacketID{}, errors.New(NotFoundErr)
	}

	// See if our packet is the oldest, then it cannot have a predecessor (as the predecessor would be older)
	currentPointer := m.PacketMap[key].listPointer
	if m.queue.Front() == currentPointer {
		// Cannot get Predecessor of oldest element, throw some error
		return ErrorRatePacketID{}, errors.New(NotFoundErr)
	}

	// Current packet at least the second oldest, get the predecessor
	predecessorPointer := currentPointer.Prev()
	if predecessorPointer == nil {
		// Handle Error, but that should not be able to happen
		return ErrorRatePacketID{}, errors.New(NotFoundErr)
	}

	// All is fine, return the predecessor
	predecessorKey := predecessorPointer.Value.(ErrorRatePacketID)
	return predecessorKey, nil
}

func (m *RecordData) GetTimestamp() time.Time {
	return m.timestamp
}

func (m *RecordData) GetOutDirection() bool {
	return m.outgoingDirection
}

func (m *RecordData) GetPayloadSize() uint32 {
	return m.payloadSize
}

func (m *RecordData) GetPacketType() int {
	return m.packetType
}
