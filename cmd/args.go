package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// unboundedArgs is the upper bound of a verb that takes any number of
// arguments.
const unboundedArgs = -1

// noArgs is the validator for a verb that takes no arguments.
func noArgs() cobra.PositionalArgs {
	return argCount(0, 0)
}

// exactArgs is the validator for a verb that takes exactly count
// arguments.
func exactArgs(count int) cobra.PositionalArgs {
	return argCount(count, count)
}

// argCount is the one positional-argument validator every verb uses. It
// reports the count the verb accepts and never repeats an argument.
//
// A value typed or pasted in the wrong place is the usual way a secret
// reaches a command line, so a usage error must not carry it into a
// terminal scrollback or a log file. Cobra's own validators are not safe
// for that: cobra.NoArgs quotes the stray argument as an unknown command,
// and a command with no validator at all falls back to a legacy check
// that does the same.
//
// maximum is unboundedArgs for a verb with no upper bound.
func argCount(minimum, maximum int) cobra.PositionalArgs {
	return func(cobraCmd *cobra.Command, args []string) error {
		switch {
		case len(args) < minimum:
			return fmt.Errorf("too few arguments: %s accepts %s", cobraCmd.Name(), acceptedArgs(minimum, maximum))
		case maximum != unboundedArgs && len(args) > maximum:
			return fmt.Errorf("too many arguments: %s accepts %s", cobraCmd.Name(), acceptedArgs(minimum, maximum))
		default:
			return nil
		}
	}
}

// acceptedArgs words the argument count a verb accepts.
func acceptedArgs(minimum, maximum int) string {
	switch {
	case maximum == 0:
		return "no arguments"
	case maximum == unboundedArgs:
		return "at least " + pluralArgs(minimum)
	case minimum == maximum:
		return pluralArgs(maximum)
	default:
		return "at most " + pluralArgs(maximum)
	}
}

// pluralArgs renders a count with its noun, such as "1 argument".
func pluralArgs(count int) string {
	if count == 1 {
		return "1 argument"
	}

	return strconv.Itoa(count) + " arguments"
}
