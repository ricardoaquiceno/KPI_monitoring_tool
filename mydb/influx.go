package mydb

import (
	"context"
	"fmt"
	"gopacket_analysis/models"
	"time"

	"github.com/InfluxCommunity/influxdb3-go/influxdb3"
	"github.com/apache/arrow/go/v15/arrow"
)

// ik token
// const token = "SSdhooCZ58xz2ipWbvsymsgXLVS2qnD3xlxnV3JVcIrPocXPRIu3aJ6D2AulCzxIbdUsveSOVTrKaGcyyWohpA=="
const token = "40e954imsfRURfnSxuxz1iuQwtQdI-Z4kJyw0vkR5731PDWdZ4mppFPS4WWMSSgipmz-2TSrV30xO3ta1rPIZA=="

func writeDummy() {
	// Create client
	url := "https://eu-central-1-1.aws.cloud2.influxdata.com"

	// Create a new client using an InfluxDB server base URL and an authentication token
	client, err := influxdb3.New(influxdb3.ClientConfig{
		Host:  url,
		Token: token,
	})

	if err != nil {
		panic(err)
	}
	// Close client at the end and escalate error if present
	defer func(client *influxdb3.Client) {
		err := client.Close()
		if err != nil {
			panic(err)
		}
	}(client)

	database := "test"
	data := map[string]map[string]interface{}{
		"point1": {
			"location": "Klamath",
			"species":  "bees",
			"count":    23,
		},
		"point2": {
			"location": "Portland",
			"species":  "ants",
			"count":    30,
		},
		"point3": {
			"location": "Klamath",
			"species":  "bees",
			"count":    28,
		},
		"point4": {
			"location": "Portland",
			"species":  "ants",
			"count":    32,
		},
		"point5": {
			"location": "Klamath",
			"species":  "bees",
			"count":    29,
		},
		"point6": {
			"location": "Portland",
			"species":  "ants",
			"count":    40,
		},
	}

	// Write data
	/*
		options := influxdb3.WriteOptions{
			Database: database,
		}*/
	dbOption := influxdb3.WithDatabase(database)
	for key := range data {
		point := influxdb3.NewPointWithMeasurement("census").
			SetTag("location", data[key]["location"].(string)).
			SetField(data[key]["species"].(string), data[key]["count"])
		points := []*influxdb3.Point{point}
		if err := client.WritePoints(context.Background(), points, dbOption); err != nil {
		}
		/*if err = client.WritePointsWithOptions(context.Background(), &options, point); err != nil {
			panic(err)
		}*/

		time.Sleep(1 * time.Second) // separate points by 1 second
	}
}

func ReadDummy() {
	// Create client
	url := "https://eu-central-1-1.aws.cloud2.influxdata.com"

	// Create a new client using an InfluxDB server base URL and an authentication token
	client, err := influxdb3.New(influxdb3.ClientConfig{
		Host:  url,
		Token: token,
	})

	if err != nil {
		panic(err)
	}
	// Close client at the end and escalate error if present
	defer func(client *influxdb3.Client) {
		err := client.Close()
		if err != nil {
			panic(err)
		}
	}(client)

	database := "test"
	// Execute query
	query := `
		SELECT *
    	FROM 'census'
        WHERE time >= now() - interval '3 hour'
		AND ('bees' IS NOT NULL OR 'ants' IS NOT NULL)`

	iterator, err := client.Query(context.Background(), query, influxdb3.WithDatabase(database))

	if err != nil {
		panic(err)
	}

	for iterator.Next() {
		value := iterator.Value()

		location := value["location"]
		ants := value["ants"]
		if ants == nil {
			ants = 0
		}
		bees := value["bees"]
		if bees == nil {
			bees = 0
		}
		tms := value["time"].(arrow.Timestamp)
		tm := tms.ToTime(arrow.Nanosecond)

		fmt.Printf("in %s are %d ants and %d bees at %s \n", location, ants, bees, tm.Format("2006-01-02 15:04:05"))
	}
}

func InfInsertStat(packets models.PacketCounts) {
	if len(packets) == 0 {
		return
	}
	// Create client
	url := "https://eu-central-1-1.aws.cloud2.influxdata.com"

	// Create a new client using an InfluxDB server base URL and an authentication token
	client, err := influxdb3.New(influxdb3.ClientConfig{
		Host:  url,
		Token: token,
	})

	if err != nil {
		panic(err)
	}
	// Close client at the end and escalate error if present
	defer func(client *influxdb3.Client) {
		err := client.Close()
		if err != nil {
			panic(err)
		}
	}(client)

	database := "gopacket"
	dbOption := influxdb3.WithDatabase(database)
	var points []*influxdb3.Point
	for typ, count := range packets {
		point := influxdb3.NewPointWithMeasurement("stats").
			SetTag("location", typ).
			SetField("count", count)
		points = append(points, point)
	}
	if err := client.WritePoints(context.Background(), points, dbOption); err != nil {
		panic(err)
	}
}
