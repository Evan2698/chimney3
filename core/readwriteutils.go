package core

import (
	"chimney3-go/utils"
	"errors"
	"log"
	"net"
)

func ReadXBytes(bytes uint32, buffer []byte, con net.Conn) ([]byte, error) {
	defer utils.Trace("readXBytes.readXBytes")()
	if bytes <= 0 {
		return nil, errors.New("0 bytes can not read! ")
	}

	var index uint32
	var err error
	var n int
	for {
		n, err = con.Read(buffer[index:])
		log.Println("read from socket size: ", n, err)
		if err != nil {
			log.Println("error on read_bytes_from_socket ", n, err)
			break
		}
		index = index + uint32(n)

		if index >= bytes {
			log.Println("read count for output ", index, err)
			break
		}
	}
	if index == bytes {
		err = nil
	}

	log.Println("read result size: ", index, err)
	return buffer[:bytes], err
}

func WriteXBytes(buffer []byte, con net.Conn) (int, error) {
	defer utils.Trace("writeXBytes.writeXBytes")()
	nbytes := uint32(len(buffer))
	var index uint32 = 0
	var err error
	var n int
	for {
		n, err = con.Write(buffer[index:])
		if err != nil {
			log.Println("write bytes error! ", n, err)
			break
		}
		index = index + uint32(n)
		if index >= nbytes {
			break
		}
	}
	if index == nbytes {
		err = nil
	}

	log.Println("writeXBytes >>>>>>", n, err)

	return int(index), err
}
