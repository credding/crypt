package flags

import (
	"os"
)

func FileRead() *File {
	return &File{flag: os.O_RDONLY}
}

func FileReadWrite() *File {
	return &File{flag: os.O_RDWR|os.O_CREATE, mode: 0666}
}

type File struct {
	file *os.File
	flag int
	mode os.FileMode
}

func (f *File) File() *os.File {
	return f.file
}

func (f *File) String() string {
	if f.file == nil {
		return ""
	}
	return f.file.Name()
}

func (f *File) Set(value string) error {
	file, err := os.OpenFile(value, f.flag, f.mode)
	if err != nil {
		return err
	}
	f.file = file
	return nil
}

func (f *File) Type() string {
	return "file"
}
