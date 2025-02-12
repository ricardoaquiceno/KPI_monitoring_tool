// Package newFlowMap implements a Flow Map with a maximum map size and automatic deletion of old records when the size
// cap is reached.
//
// The Package is split into three files.
//
// The FlowMap file contains all implementations for the top level of the Flow Map, which will save statistics about the
// Network Flow identified by the Source and Destination IP. This Map contains some basic statistics only, relying on
// the ApplicationMap for actual statistics such as throughput or latency or Application specific metrics.
//
// The ApplicationMap file contains the implementation for the lower level of the Flow Map, wich will save statistics
// about the Applications that belong to a flow. These are identified by the Transport Protocol and Ports. The
// ApplicationMap stores most of the actual statistically important data such as throughput and other application
// specific measurements such as TCP Latency, TCP Error Rate, or QUIC Latency. It also contains Potential Application
// Types (i.e. Audio/Video/Web Browsing) and Potential Traffic Types (i.e. QUIC/HTTP/DNS/...)
package newFlowMap

import (
	"container/list"
	"errors"
	"fmt"
	"gopacket_analysis/config"
	"net"
	"time"
)

// FlowMapElement contains the data of the FlowMap, which is the Network Protocol, IP Addresses as well as the
// ApplicationMap, last packet time and the list pointer required for FlowMap maintenance
type FlowMapElement struct {
	NetworkProtocol string // i.e. IPv4 or IPv6 or something else?
	SrcIP           net.IP
	DstIP           net.IP
	LastPacketTime  time.Time

	ApplicationMap *ApplicationMap
	listPointer    *list.Element
}

// FlowMapID consists of the NetFlowHash, which is just the packet.NetworkLayer().NetworkFlow().FastHash() consisting of
// a hash of the source and destination IP address to uniquely and bidirectionally identify a Network Flow
type FlowMapID struct {
	NetFlowHash uint64
}

// FlowMap is the main structure that contains the Flows Map with the actual data, as well as the queue and maxSize wich
// are required for maintaining the FlowMap
type FlowMap struct {
	// Flows are based on destination and source IP
	Flows map[FlowMapID]*FlowMapElement

	// The queue is actually an array that emulates a queue and is used to keep track of the age/order of the packets
	queue *list.List
	// Helper variables of the queue
	maxSize int
}

// NewFlowMap is a helper function for creating a new FlowMap
func NewFlowMap(size int) *FlowMap {
	return &FlowMap{
		Flows:   make(map[FlowMapID]*FlowMapElement),
		queue:   list.New(),
		maxSize: size,
	}
}

// Contains returns true if the FlowMap contains the Flow, identified by the FlowMapID
func (m *FlowMap) Contains(key FlowMapID) bool {
	_, ok := m.Flows[key]
	return ok
}

// Len returns the length of the FlowMap, i.e. the number of distinct Flows
func (m *FlowMap) Len() int {
	return len(m.Flows)
}

// Add a new FlowMapElement to the FlowMap and return pointer to it.
// This function should only be called to add an actually new FlowMapElement, for adding info about an existing
// FlowMapElement please use the AddPacketInfo function.
// If the Element is already present, just return the pointer to it as well as an error indicating it already exists
// (debug only). If we are at max length the function will automatically delete the oldest packet first.
func (m *FlowMap) Add(key FlowMapID, element *FlowMapElement) (error, *FlowMapElement) {
	// If element exists already, just return pointer to it
	actualElement, elementExists := m.Flows[key]
	if elementExists {
		return errors.New(DupFlowErr), actualElement
	}

	// If the queue is full, remove the oldest entry
	if len(m.Flows) == m.maxSize {
		err := m.RemoveOldest()
		if err != nil {
			if err.Error() == AlreadyDeletedErr {
				fmt.Println("Got an AlreadyDeletedErr while removing the oldest flow in order to add a new one")
				return err, nil
			}
		}
		if len(m.Flows) == m.maxSize {
			fmt.Println("Shit")
			return errors.New(AddFlowError), nil
		}
	}

	// Finally add the current entry
	// Add Key to the back of the Queue
	queuePointer := m.queue.PushBack(key)

	// As the map stores a copy of the element I need to return the actual pointer to the element in the Flows map
	element.listPointer = queuePointer
	m.Flows[key] = element
	return nil, element
}

// RemoveOldest removes the oldest Flow from the PassiveLatencyMap
func (m *FlowMap) RemoveOldest() error {
	// Delete the oldest element and get its value cast to a FlowMapID
	key := m.queue.Remove(m.queue.Front()).(FlowMapID)

	mapLen1 := m.Len()

	// Actual Deletion of element in map
	delete(m.Flows, key)

	mapLen2 := m.Len()
	queueLen := m.queue.Len()

	if mapLen1 == mapLen2 || mapLen2 != queueLen {
		return errors.New(DeleteOldestErr)
	}
	return nil
}

// AddPacket adds information from a Packet to the FlowMap, which in turn adds it to the underlying ApplicationMap.
// the basicFlowMapInfo is a FlowMapElement which only contains the mandatory NetworkProtocol, Src and Dst IP as well as
// the LastPacketTime
func (m *FlowMap) AddPacket(flowKey FlowMapID, basicFlowMapInfo *FlowMapElement, appKey ApplicationMapID,
	basicApplicationElement *ApplicationMapElement, optionalApplicationParameters ApplicationMapOptionalParameters) error {
	// 1. Check if flow exists, and add it if not by using m.Add
	err, flowMapElement := m.Add(flowKey, basicFlowMapInfo)
	if flowMapElement == nil {
		return err
	}

	// 1.1 Maybe check that data from basicFlowMapInfo matches with the actual FlowMapElement if it already exists?
	if err != nil && err.Error() == DupFlowErr {
		// ToDo: add FlowMapElement comparison
	}

	// 2. Check if ApplicationMap exists and else create one
	applicationMap := flowMapElement.ApplicationMap
	if applicationMap == nil {
		applicationMap = NewApplicationMap(config.Performance.ApplicationMapSize)
		flowMapElement.ApplicationMap = applicationMap
	}

	// 3. Finally Add the Packet to the ApplicationMap
	err, _ = applicationMap.Add(appKey, basicApplicationElement, optionalApplicationParameters)
	if err != nil {
		return err
	}
	return nil
}

// Remove the specified Flow from the FlowMap
// Can throw following Errors: "AlreadyDeletedErr", "DeleteOldestErr"
func (m *FlowMap) Remove(flowKey FlowMapID) error {
	if !m.Contains(flowKey) {
		// Nothing to delete, done
		return errors.New(AlreadyDeletedErr)
	} else {
		mapLen1 := m.Len()

		record := m.Flows[flowKey]

		// Remove packet from Queue
		m.queue.Remove(record.listPointer)

		// Delete packet from map
		delete(m.Flows, flowKey)

		mapLen2 := m.Len()
		queueLen := m.queue.Len()
		if mapLen1 == mapLen2 || mapLen2 != queueLen {
			return errors.New(DeleteOldestErr)
		}
		return nil
	}
}

// ClearOld will clear all records in the FlowMap that are older than the duration passed as an argument.
// This will garbage collect Flows deemed irrelevant as they appear to no further communications.
func (m *FlowMap) ClearOld(maxAge time.Duration) {
	for flowKey, flow := range m.Flows {
		if time.Since(flow.LastPacketTime) > maxAge {
			err := m.Remove(flowKey)
			if err != nil {
			}
		}
	}
}

// StatisticsAndMaintenance will be run every second to calculate the statistics and perform maintenance on the FlowMap
// and the ApplicationMap of each of the Flows
func (m *FlowMap) StatisticsAndMaintenance() (int, int, uint64, uint64, int) {
	// ToDo: Implement the statistics part here first
	//  Might be able to do maintenance and statistics in one run through the flows
	var packetsIn, packetsOut int
	var bytesIncoming uint64
	var bytesOutgoing uint64
	var quicPackets int

	// Maintenance Part
	maxAge := time.Duration(config.Config.PerformanceSettings.FlowMapMaxAgeSeconds) * time.Second
	for flowKey, flow := range m.Flows {
		// Check if Flow is too old
		if time.Since(flow.LastPacketTime) > maxAge {
			err := m.Remove(flowKey)
			if err != nil {
			}
		} else {
			// Flow not too old, Gather Flow statistics
			// Still ToDo

			// Check if Application is too old
			for appKey, app := range flow.ApplicationMap.Applications {
				if time.Since(app.LastPacketTime) > maxAge {
					err := flow.ApplicationMap.Remove(appKey)
					if err != nil {
					}
				} else {
					// App is not too old, gather statistics
					// Still ToDo
					packetsIn += app.Measurements.PacketsIn
					app.Measurements.PacketsIn = 0
					packetsOut += app.Measurements.PacketsOut
					app.Measurements.PacketsOut = 0

					bytesOutgoing += app.Measurements.SizeBytesOut
					bytesIncoming += app.Measurements.SizeBytesIn

					app.Measurements.SizeBytesOut = 0
					app.Measurements.SizeBytesIn = 0

					quicPackets += app.Measurements.QuicPackets
					app.Measurements.QuicPackets = 0
				}
			}
		}
	}
	return packetsIn, packetsOut, bytesIncoming, bytesOutgoing, quicPackets
}
