package GoSNMPServer

import "github.com/pkg/errors"
import "github.com/slayercat/gosnmp"
import "strings"
import "strconv"

func getPktContextOrCommunity(i *gosnmp.SnmpPacket) string {
	if i.Version == gosnmp.Version3 {
		return i.ContextName
	} else {
		return i.Community
	}
}

func copySnmpPacket(i *gosnmp.SnmpPacket) gosnmp.SnmpPacket {
	var ret gosnmp.SnmpPacket = *i
	if i.SecurityParameters != nil {
		ret.SecurityParameters = i.SecurityParameters.Copy()
	}
	return ret
}

func oidToByteString(oid string) string {
	xi := strings.Split(oid, ".")
	out := []rune{}
	for id, each := range xi {
		if each == "" {
			if id == 0 {
				continue
			} else {
				panic(errors.Errorf("oidToByteString not valid id. value=%v", oid))
			}

		}
		i, err := strconv.ParseInt(each, 10, 32)
		if err != nil {
			panic(err)
		}
		out = append(out, rune(i))
	}
	return string(out)
}

func oidCompare(oidx string, oidy string) bool {
	xi := strings.Split(oidx, ".")
	yi := strings.Split(oidy, ".")
	for id, each := range xi {
		i, err := strconv.ParseInt(each, 10, 32)
		if err != nil {
			panic(err)
		}
		if len(yi) <= id {
			return true
		}
		j, err := strconv.ParseInt(yi[id], 10, 32)
		if err != nil {
			panic(err)
		}
		if i > j {
			return true
		} else if i < j {
			return false
		}
	}
	return true
}

// IsValidObjectIdentifier will check a oid string is valid oid
func IsValidObjectIdentifier(oid string) (result bool) {
	defer func() {
		if err := recover(); err != nil {
			result = false
			return
		}
	}()
	if len(oid) == 0 {
		return false
	}
	oidToByteString(oid)
	return true
}
