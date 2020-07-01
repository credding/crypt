package encoding

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

var UnsupportedEncoding = errors.New("unsupported encoding")

type Encoding interface {
	Type() string
	TryUnmarshal(data []byte) (interface{}, error)
}

type Encodings []Encoding

func (formats Encodings) Decode(in io.Reader) (interface{}, error) {
	data, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return formats.Unmarshal(data)
}

func (formats Encodings) Unmarshal(data []byte) (interface{}, error) {
	for _, format := range formats {
		decoded, err := format.TryUnmarshal(data)
		if err != nil && !errors.Is(err, UnsupportedEncoding) {
			return nil, err
		}
		if decoded != nil {
			return decoded, nil
		}
	}
	return nil, formats.unsupportedEncoding()
}

func (formats Encodings) unsupportedEncoding() error {
	switch len(formats) {
	case 0:
		return UnsupportedEncoding
	case 1:
		return fmt.Errorf("%w: expected %s", UnsupportedEncoding, formats[0].Type())
	}

	message := strings.Builder{}
	message.WriteString("expected ")
	for _, format := range formats[:len(formats)-1] {
		message.WriteString(format.Type())
		message.WriteString(", ")
	}
	message.WriteString("or ")
	message.WriteString(formats[len(formats)-1].Type())

	return fmt.Errorf("%w: %s", UnsupportedEncoding, message.String())
}
