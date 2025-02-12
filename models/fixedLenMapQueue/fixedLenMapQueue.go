package fixedLenMapQueue

import (
	"errors"
	"fmt"
	"gopacket_analysis/models"
)

const (
	DupErr = "duplicate packet"
)

type PacketID struct {
	Sequence        uint32
	Acknowledgement uint32
	PayloadSize     int
	ThisFlowId      models.FlowID
}

type LastPacketsMap struct {
	queue     []PacketID
	maxSize   int
	index     int
	PacketMap map[PacketID]interface{}
}

func NewLastPacketsMap(size int) *LastPacketsMap {
	return &LastPacketsMap{
		queue:     make([]PacketID, size),
		maxSize:   size,
		index:     0,
		PacketMap: make(map[PacketID]interface{}),
	}
}

func (this *LastPacketsMap) Add(key PacketID, value interface{}) error {
	if this.Contains(key) {
		return errors.New(DupErr)
	}

	// Remove the oldest entry if the queue is full
	if len(this.PacketMap) == this.maxSize {
		delete(this.PacketMap, this.queue[this.index])
		this.queue[this.index] = key
		this.PacketMap[key] = value
		this.index++
	} else {
		this.queue[this.index] = key
		this.PacketMap[key] = value
		this.index++
	}

	// If the index reaches the end of the slice, wrap around to the beginning
	if this.index == this.maxSize {
		this.index = 0
	}
	return nil
}

func (this *LastPacketsMap) Contains(key PacketID) bool {
	_, ok := this.PacketMap[key]
	return ok
}

func (this *LastPacketsMap) Len() int {
	return len(this.PacketMap)
}

func main() {
	x := NewLastPacketsMap(2)
	fmt.Println(x.queue)
	fmt.Println(x.PacketMap)
	var err error
	err = x.Add(PacketID{
		Sequence:        1,
		Acknowledgement: 1,
		PayloadSize:     1,
	}, "val 1")
	fmt.Println(x.queue)
	err = x.Add(PacketID{
		Sequence:        2,
		Acknowledgement: 2,
		PayloadSize:     2,
	}, "val 2")
	fmt.Println(x.queue)
	err = x.Add(PacketID{
		Sequence:        3,
		Acknowledgement: 3,
		PayloadSize:     3,
	}, "val 3")
	fmt.Println(x.queue)
	err = x.Add(PacketID{
		Sequence:        2,
		Acknowledgement: 2,
		PayloadSize:     2,
	}, "val 3")
	if err != nil && err.Error() == DupErr {
		fmt.Println("Found a duplicate packet")
	}
	fmt.Println(x.queue)
	err = x.Add(PacketID{
		Sequence:        4,
		Acknowledgement: 4,
		PayloadSize:     4,
	}, "val 4")
	fmt.Println(x.queue)
	err = x.Add(PacketID{
		Sequence:        5,
		Acknowledgement: 5,
		PayloadSize:     5,
	}, "val 5")
	fmt.Println(x.queue)

	fmt.Println(x.PacketMap)
}
