package logger

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogPrint(t *testing.T) {
	var waitGroup sync.WaitGroup
	goRoutineCount := 100
	originalStdout := os.Stdout
	read, write, _ := os.Pipe()
	os.Stdout = write

	// run go routines that each make a call
	// to the log.print function and print
	// a unique string
	for i := 0; i < goRoutineCount; i++ {
		waitGroup.Add(1)
		go func(counter int) {
			defer waitGroup.Done()
			write.Write([]byte(fmt.Sprintf("a%d.", counter)))
		}(i)
	}

	waitGroup.Wait()

	write.Close()
	output, _ := ioutil.ReadAll(read)

	os.Stdout = originalStdout

	// check for each of the
	// unique strings printed
	// by the go routines
	for j := 0; j < goRoutineCount; j++ {
		assert.Regexp(t, regexp.MustCompile(fmt.Sprintf("a%d", j)), string(output))
	}
}

func TestGetLevelInt(t *testing.T) {
	integer := getLevelInt("Trace")
	assert.Equal(t, TRACE, integer)

	integer = getLevelInt("DEBUG")
	assert.Equal(t, DEBUG, integer)

	integer = getLevelInt("info")
	assert.Equal(t, INFO, integer)

	integer = getLevelInt("warn")
	assert.Equal(t, WARN, integer)

	integer = getLevelInt("fatal")
	assert.Equal(t, FATAL, integer)

	integer = getLevelInt("none")
	assert.Equal(t, INFO, integer)
}

func TestIsDisabledFor(t *testing.T) {
	configuredLevel = TRACE

	enabled := isDisabledFor("trace")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("debug")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("info")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("warn")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("fatal")
	assert.Equal(t, false, enabled)

	configuredLevel = DEBUG

	enabled = isDisabledFor("trace")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("debug")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("info")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("warn")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("fatal")
	assert.Equal(t, false, enabled)

	configuredLevel = INFO

	enabled = isDisabledFor("trace")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("debug")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("info")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("warn")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("fatal")
	assert.Equal(t, false, enabled)

	configuredLevel = WARN

	enabled = isDisabledFor("trace")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("debug")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("info")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("warn")
	assert.Equal(t, false, enabled)
	enabled = isDisabledFor("fatal")
	assert.Equal(t, false, enabled)

	configuredLevel = FATAL

	enabled = isDisabledFor("trace")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("debug")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("info")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("warn")
	assert.Equal(t, true, enabled)
	enabled = isDisabledFor("fatal")
	assert.Equal(t, false, enabled)
}
