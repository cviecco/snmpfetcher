package snmpfetcher

import (
	"fmt"
	"github.com/soniah/gosnmp"
	"strconv"
	"time"
)

const systemmib_BASE = ".1.3.6.1.2.1.1"
const interfaces_BASE = ".1.3.6.1.2.1.2"
const hrSystem_BASE = ".1.3.6.1.2.1.25.1"
const hrStorage_BASE = ".1.3.6.1.2.1.25.2"
const hrDevice_BASE = ".1.3.6.1.2.1.25.3"
const mib2_ifmib_BASE = ".1.3.6.1.2.1.31"
const ucdDaemons_BASE = ".1.3.6.1.4.1.2021.2"
const ucdMemory_BASE = ".1.3.6.1.4.1.2021.4"
const ucdLaTable_BASE = ".1.3.6.1.4.1.2021.10"
const ucdCPU_BASE = ".1.3.6.1.4.1.2021.11"

type SNMPDatum struct {
	Type  gosnmp.Asn1BER
	Value interface{}
}

/* Notes:
   For the aim project, the ucd oid where added. Resulting in 17 RTT to fetch all the data of a single vm.
   And a time of 34 ms against the loopback interface (for the actual data transmit).
*/

func fetch_some(session gosnmp.GoSNMP) (map[string]SNMPDatum, error) {
	targetoids := []string{systemmib_BASE,
		interfaces_BASE,
		hrSystem_BASE,
		hrStorage_BASE,
		hrDevice_BASE,
		mib2_ifmib_BASE,
		ucdDaemons_BASE,
		ucdMemory_BASE,
		ucdLaTable_BASE,
		ucdCPU_BASE}

	m := make(map[string]SNMPDatum)

	for _, oid := range targetoids {
		results, err := session.BulkWalkAll(oid)
		if err != nil {
			results, err = session.WalkAll(oid)
			if err != nil {
				return m, err
			}
		}
		for _, result_pdu := range results {
			//printValue(result_pdu)
			datum := SNMPDatum{Type: result_pdu.Type, Value: result_pdu.Value}
			m[result_pdu.Name] = datum
		}
	}
	return m, nil
}

func printValue(pdu gosnmp.SnmpPDU) error {
	fmt.Printf("%s = ", pdu.Name)

	switch pdu.Type {
	case gosnmp.OctetString:
		b := pdu.Value.([]byte)
		fmt.Printf("STRING: %s\n", string(b))
	default:
		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}
	return nil
}

// GetIfaceData transnforms opaque data struct returned by the fetcher functions
// and transforms them into inteface data.
func GetIfaceData(hostData map[string]SNMPDatum) (map[string]map[string]uint64, error) {
	ifacemetric2oidPrefix := map[string]string{
		//"address" : ".1.3.6.1.2.1.2.2.1.6",
		"mtu":        ".1.3.6.1.2.1.2.2.1.4",
		"rx-errors":  ".1.3.6.1.2.1.2.2.1.14",
		"tx-errors":  ".1.3.6.1.2.1.2.2.1.20",
		"rx-data":    ".1.3.6.1.2.1.31.1.1.1.6",
		"rx-packets": ".1.3.6.1.2.1.31.1.1.1.10",
		"tx-data":    ".1.3.6.1.2.1.31.1.1.1.10",
		"tx-packets": ".1.3.6.1.2.1.31.1.1.1.11",
	}

	name2index := make(map[string]int)
	for i := 1; ; i++ {
		datum, ok := hostData[".1.3.6.1.2.1.31.1.1.1.1."+strconv.Itoa(i)]
		if !ok {
			break
		}
		ifaceBytes := datum.Value.([]byte)
		ifaceName := string(ifaceBytes)
		name2index[ifaceName] = i
	}

	ifaceMetrics := make(map[string]map[string]uint64)
	for ifaceName, oidIndex := range name2index {
		mm := make(map[string]uint64)
		ifaceMetrics[ifaceName] = mm
		for metricName, OidPrefix := range ifacemetric2oidPrefix {
			oid := OidPrefix + "." + strconv.Itoa(oidIndex)
			datum, ok := hostData[oid]
			if !ok {
				continue
			}
			bigIntVal := gosnmp.ToBigInt(datum.Value)
			ifaceMetrics[ifaceName][metricName] = bigIntVal.Uint64()
		}
	}
	return ifaceMetrics, nil
}

// FetchSimpleDataSNMP2c fetches data from an SNMP tartget using v2 udp statistics
// The collected data includes Linux SNMP subtrees. If any of the predefined trees
// is not able to be collected the function will return failure.
// On success an object (that should be considered opaque) is returned.
func FetchSimpleDataSNMP2c(host string, port uint16, community string) (map[string]SNMPDatum, error) {
	snmpSession := &gosnmp.GoSNMP{
		Target:    host,
		Port:      port,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(3) * time.Second,
		Retries:   2,
	}
	err := snmpSession.Connect()
	if err != nil {
		return nil, err
	}
	defer snmpSession.Conn.Close()
	data, err := fetch_some(*snmpSession)
	if err != nil {
		return nil, err
	}
	return data, nil
}
