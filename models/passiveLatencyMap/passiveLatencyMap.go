// Package passiveLatencyMap enables the comfortable storage and calculation of information that is needed to give RTT
// Latency measurements for TCP (and other potential) Packets. We store only the Packet Timestamp using a
// PassiveLatencyPacketID as the key with a Flow ID and the Expected Acknowledgement ID.
//
// The original development of the RTT Latency measurement saw a big map of all TCP Flows and their packets. The Packet
// Info included much data like Source and Destination IP/Port, Ack and Seq Number, Payload Size, Direction, and even
// the TCP Flags. That map grew too fast and hence lead to a bit slowdown, as a measurement needed to go through all
// packets of the flow to find a correlating packet for latency measurement.
//
// The second implementation used a Fixed Length Map Queue which was not correctly implemented I think.
// Basically it tried to calculate rtt and duplicate packets by using a map supported by a list to try and create what
// has been implemented here. It did not work as the manipulation of the map and list was not handled correctly.
//
// This lead to this development which correctly implements the link between the packet map and the queue to enable a
// map queue that enables both an efficient way of accessing the elements (by use of the map key), as well as enabling a
// maximum length for that map queue in order to not save every package forever.
package passiveLatencyMap

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
	TooLongLatencyErr = "packet latency too long"
)

// PassiveLatencyPacketID is a composite key using the flow id of the outgoing packet as well as the expected
// acknowledgement id of the packet.
type PassiveLatencyPacketID struct {
	ThisFlowId    models.FlowID
	ExpectedAckID uint32
}

type Record struct {
	timestamp   time.Time
	listPointer *list.Element
}

// PassiveLatencyMap is a structure that contains a PacketMap which contains the actually relevant data of the packet,
// using the PassiveLatencyPacketID as an identifier. This PassiveLatencyMap automatically keeps up to maxSize packets
// (set in the initialization method NewPassiveLatencyMap) and will delete the oldest packet if the maxSize was reached.
// This is accomplished using a list that acts as a queue and keeps track of the order of the packets.
type PassiveLatencyMap struct {
	// PacketMap Contains the relevant information of the packet (like a timestamp) and can be accessed using the PassiveLatencyPacketID
	PacketMap map[PassiveLatencyPacketID]Record

	// The queue is actually an array that emulates a queue and is used to keep track of the age/order of the packets
	queue *list.List
	// Helper variables of the queue
	maxSize int
}

// NewPassiveLatencyMap is a helper function for creating a new PassiveLatencyMap
func NewPassiveLatencyMap(size int) *PassiveLatencyMap {
	return &PassiveLatencyMap{
		PacketMap: make(map[PassiveLatencyPacketID]Record),
		queue:     list.New(),
		maxSize:   size,
	}
}

// Contains returns true if the PassiveLatencyMap contains the packet
func (m *PassiveLatencyMap) Contains(key PassiveLatencyPacketID) bool {
	_, ok := m.PacketMap[key]
	return ok
}

// Len returns the length of the PacketMap. Note that this may differ from the size of the queue if the queue is at max
// length, but we remove a Packet that was already acked.
func (m *PassiveLatencyMap) Len() int {
	return len(m.PacketMap)
}

// Add a new packet to the PassiveLatencyMap. If the packet is already present, return a DupErr. If we are at max length
// the function will automatically delete the oldest packet first.
func (m *PassiveLatencyMap) Add(key PassiveLatencyPacketID, timestamp time.Time) error {
	// Sent packet already in Map, so this packet is a duplicate
	if m.Contains(key) {
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
		timestamp:   timestamp,
		listPointer: queuePointer,
	}
	m.PacketMap[key] = record
	return nil
}

// RemoveOldest removes the oldest Packet from the PassiveLatencyMap
func (m *PassiveLatencyMap) RemoveOldest() error {
	// Delete the oldest element and get its value casted to a Packet ID
	key := m.queue.Remove(m.queue.Front()).(PassiveLatencyPacketID)

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
// Can throw following Errors: "AlreadyDeletedErr", "DeleteOldestErr"
func (m *PassiveLatencyMap) Remove(key PassiveLatencyPacketID) error {
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

// ClearOld will clear all records in the PLM that are older than the duration passed as an argument.
// This will garbage collect packets deemed irrelevant as the latency might be too high.
// Still up for debate if I need this function here, or not.
func (m *PassiveLatencyMap) ClearOld(maxAge time.Duration) {
	for packetID, record := range m.PacketMap {
		if time.Since(record.timestamp) > maxAge {
			err := m.Remove(packetID)
			if err != nil {
			}
		}
	}
}

// CalculateLatency tries to calculate the latency between the time of sending the outgoing packet and the time when the
// Packet was acknowledged. If the Incoming Acknowledgement does not belong to a known packet it returns an NotFoundErr,
// which can happen either if the acknowledgement took so long that the outgoing packet is not in the map anymore, or it
// might happen when the outgoing packet was already acknowledged, hence deleted from the map.
func (m *PassiveLatencyMap) CalculateLatency(key PassiveLatencyPacketID, ackTime time.Time, timeoutMilliseconds int64) (time.Duration, error) {
	if !m.Contains(key) {
		return 0, errors.New(NotFoundErr)
	} else {
		record := m.PacketMap[key]

		rtt := ackTime.Sub(record.timestamp)
		err := m.Remove(key)
		if err != nil {
			fmt.Print()
		}
		if rtt.Milliseconds() > timeoutMilliseconds {
			return rtt, errors.New(TooLongLatencyErr)
		}
		return rtt, nil
	}
}
