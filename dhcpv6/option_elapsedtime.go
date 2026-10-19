package dhcpv6

import (
	"fmt"
	"math"
	"time"

	"github.com/u-root/uio/uio"
)

// OptElapsedTime returns an Elapsed Time option as defined by RFC 3315 Section
// 22.9.
func OptElapsedTime(dur time.Duration) Option {
	return &optElapsedTime{ElapsedTime: dur}
}

type optElapsedTime struct {
	ElapsedTime time.Duration
}

func (*optElapsedTime) Code() OptionCode {
	return OptionElapsedTime
}

// ToBytes marshals this option to bytes.
func (op *optElapsedTime) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	// RFC 8415 Section 21.9: 0xffff stands for any longer time.
	cs := op.ElapsedTime.Round(10*time.Millisecond) / (10 * time.Millisecond)
	buf.Write16(uint16(min(max(cs, 0), math.MaxUint16)))
	return buf.Data()
}

func (op *optElapsedTime) String() string {
	return fmt.Sprintf("%s: %s", op.Code(), op.ElapsedTime)
}

// FromBytes builds an optElapsedTime structure from a sequence of bytes.
// The input data does not include option code and length bytes.
func (op *optElapsedTime) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	op.ElapsedTime = time.Duration(buf.Read16()) * 10 * time.Millisecond
	return buf.FinError()
}
