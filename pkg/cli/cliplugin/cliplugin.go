package cliplugin

import "github.com/spf13/cobra"

type CliPlugin interface {
	Command() *cobra.Command
}

var CliPlugins map[string]CliPlugin = map[string]CliPlugin{}
