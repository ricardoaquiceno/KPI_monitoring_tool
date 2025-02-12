package influxv1

import (
	"fmt"
	_ "github.com/influxdata/influxdb1-client" // this is important because of the bug in go mod
	client "github.com/influxdata/influxdb1-client/v2"
	"gopacket_analysis/config"
	"time"
)

func CheckInfluxConnection() bool {
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     config.InfluxV1.Address,
		Username: config.InfluxV1.User,
		Password: config.InfluxV1.Password,
	})
	if err != nil {
		fmt.Println("Error creating InfluxDB Client: ", err.Error())
	}
	defer func(c client.Client) {
		err := c.Close()
		if err != nil {
			fmt.Println("Error closing InfluxDB Client: ", err.Error())
		}
	}(c)

	latency, version, pingError := c.Ping(1)
	if pingError != nil {
		fmt.Println("Error pinging InfluxDB: ", pingError.Error())
		return false
	} else {
		fmt.Println("InfluxDB Version: ", version, " Pinged with latency: ", latency)
		return true
	}
}

// WriteLine Writes line of sensor data to InfluxDB. Returns nil if successful.
func WriteLine(measurement string, tags map[string]string, fields map[string]interface{}) {
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     config.InfluxV1.Address,
		Username: config.InfluxV1.User,
		Password: config.InfluxV1.Password,
	})
	if err != nil {
		fmt.Println("Error creating InfluxDB Client: ", err.Error())
	}
	defer c.Close()

	// Create a new point batch
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:        config.InfluxV1.Database,
		Precision:       config.InfluxV1.Precision,
		RetentionPolicy: config.InfluxV1.Retention,
	})

	pt, err := client.NewPoint(measurement, tags, fields, time.Now())
	if err != nil {
		fmt.Println("Error: ", err.Error())
	}
	bp.AddPoint(pt)

	// Write the batch
	err = c.Write(bp)
	if err != nil {
		fmt.Println("Error writing InfluxDB points: ", err.Error())
	}
}
