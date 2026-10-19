package rfc1035label

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLabelsFromBytes(t *testing.T) {
	expected := []byte{
		0x9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		0x2, 'i', 't',
		0x0,
	}
	labels, err := FromBytes(expected)
	require.NoError(t, err)
	require.Equal(t, 1, len(labels.Labels))
	require.Equal(t, len(expected), labels.Length())
	require.Equal(t, expected, labels.ToBytes())
	require.Equal(t, "slackware.it", labels.Labels[0])
}

func TestLabelsFromBytesZeroLength(t *testing.T) {
	labels, err := FromBytes([]byte{})
	require.NoError(t, err)
	require.Equal(t, 0, len(labels.Labels))
	require.Equal(t, 0, labels.Length())
	require.Equal(t, []byte{}, labels.ToBytes())
}

func TestLabelsFromBytesPartialDomainName(t *testing.T) {
	// Partial domain name without trailing zero-length byte as per RFC 4704
	// Section 4.2
	expected := []byte{
		0x8, 'h', 'o', 's', 't', 'n', 'a', 'm', 'e',
	}
	labels, err := FromBytes(expected)
	require.NoError(t, err)
	require.Equal(t, 1, len(labels.Labels))
	require.Equal(t, len(expected), labels.Length())
	require.Equal(t, expected, labels.ToBytes())
	require.Equal(t, "hostname", labels.Labels[0])
}

func TestLabelsFromBytesInvalidLength(t *testing.T) {
	_, err := FromBytes([]byte{0x5, 0xaa, 0xbb}) // short length
	require.Error(t, err)
}

func TestLabelsFromBytesInvalidLengthOffByOne(t *testing.T) {
	_, err := FromBytes([]byte{0x3, 0xaa, 0xbb}) // short length
	require.Error(t, err)
}

func TestLabelsToBytes(t *testing.T) {
	expected := []byte{
		9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		2, 'i', 't',
		0,
		9, 'i', 'n', 's', 'o', 'm', 'n', 'i', 'a', 'c',
		9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		2, 'i', 't',
		0,
	}
	labels := Labels{
		Labels: []string{
			"slackware.it",
			"insomniac.slackware.it",
		},
	}
	require.Equal(t, expected, labels.ToBytes())
}

func TestLabelToBytesZeroLength(t *testing.T) {
	labels := Labels{
		Labels: []string{""},
	}
	require.Equal(t, []byte{0}, labels.ToBytes())
}

func TestCompressedLabel(t *testing.T) {
	data := []byte{
		// slackware.it
		9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		2, 'i', 't',
		0,
		// insomniac.slackware.it
		9, 'i', 'n', 's', 'o', 'm', 'n', 'i', 'a', 'c',
		192, 0,
		// mail.systemboot.org
		4, 'm', 'a', 'i', 'l',
		10, 's', 'y', 's', 't', 'e', 'm', 'b', 'o', 'o', 't',
		3, 'o', 'r', 'g',
		0,
		// systemboot.org
		192, 31,
	}
	expected := []string{
		"slackware.it",
		"insomniac.slackware.it",
		"mail.systemboot.org",
		"systemboot.org",
	}

	labels, err := FromBytes(data)
	require.NoError(t, err)
	require.Equal(t, 4, len(labels.Labels))
	require.Equal(t, expected, labels.Labels)
	require.Equal(t, len(data), labels.Length())
}

func TestShortCompressedLabel(t *testing.T) {
	data := []byte{
		// slackware.it
		9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		2, 'i', 't',
		0,
		// insomniac.slackware.it
		9, 'i', 'n', 's', 'o', 'm', 'n', 'i', 'a', 'c',
		192,
	}

	_, err := FromBytes(data)
	require.Error(t, err)
}

func TestNestedCompressedLabel(t *testing.T) {
	data := []byte{
		// it
		3, 'i', 't',
		0,
		// slackware.it
		9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		192, 0,
		// insomniac.slackware.it
		9, 'i', 'n', 's', 'o', 'm', 'n', 'i', 'a', 'c',
		192, 5,
	}
	_, err := FromBytes(data)
	require.Error(t, err)
}

func TestChainedCompressedLabel(t *testing.T) {
	data := []byte{
		// example.com
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		// a.example.com
		1, 'a', 192, 0,
		// b.a.example.com: a pointer to a name that ends with a pointer
		1, 'b', 192, 13,
	}
	labels, err := FromBytes(data)
	require.NoError(t, err)
	require.Equal(t, []string{"example.com", "a.example.com", "b.a.example.com"}, labels.Labels)
}

func TestInvalidCompressedLabel(t *testing.T) {
	for name, data := range map[string][]byte{
		"pointer to itself":                         {192, 0},
		"forward pointer":                           {192, 2, 1, 'a', 0},
		"pointer into the name":                     {1, 'a', 192, 0},
		"loop through two names":                    {1, 'a', 192, 4, 1, 'b', 192, 0},
		"pointer past the end":                      {1, 'a', 0, 192, 9},
		"loop through a moved barrier":              {6, 'q', 0xc0, 0x05, 'r', 0xc0, 0x02, 0, 0xc0, 0x02},
		"pointer into the name with a label before": {1, 'a', 0, 1, 0, 0xc0, 0x04},
		"pointed name runs past the end":            {1, 3, 0, 0xc0, 0x01},
		"reserved label type 01":                    append([]byte{0x41}, make([]byte, 65)...),
		"reserved label type 10":                    append([]byte{0x81}, make([]byte, 129)...),
	} {
		if _, err := FromBytes(data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestLongName(t *testing.T) {
	name := func(last int) []byte {
		var b []byte
		for _, n := range []int{63, 63, 63, last} {
			b = append(b, byte(n))
			b = append(b, make([]byte, n)...)
		}
		return append(b, 0)
	}
	// Three labels of 63, one of 61 and the root label: 255 octets.
	_, err := FromBytes(name(61))
	require.NoError(t, err)
	_, err = FromBytes(name(62))
	require.Error(t, err)
}

func FuzzLabel(f *testing.F) {

	f.Add([]byte{0x5, 0xaa, 0xbb})
	f.Add([]byte{0x3, 0xaa, 0xbb})

	data_0 := []byte{
		// slackware.it
		9, 's', 'l', 'a', 'c', 'k', 'w', 'a', 'r', 'e',
		2, 'i', 't',
		0,
		// insomniac.slackware.it
		9, 'i', 'n', 's', 'o', 'm', 'n', 'i', 'a', 'c',
		192, 0,
		// mail.systemboot.org
		4, 'm', 'a', 'i', 'l',
		10, 's', 'y', 's', 't', 'e', 'm', 'b', 'o', 'o', 't',
		3, 'o', 'r', 'g',
		0,
		// systemboot.org
		192, 31,
	}

	f.Add(data_0)

	f.Fuzz(func(t *testing.T, data []byte) {
		labels, err := FromBytes(data)
		if err != nil {
			return
		}
		labels.ToBytes()
	})
}
