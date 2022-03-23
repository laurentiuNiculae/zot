//go:build extended
// +build extended

package cli

import (
	"github.com/spf13/cobra"

	. "zotregistry.io/zot/pkg/cli/cliplugin"
	_ "zotregistry.io/zot/pkg/extensions/countplugin"
)

func enableCli(rootCmd *cobra.Command) {
	rootCmd.AddCommand(NewConfigCommand())
	rootCmd.AddCommand(NewImageCommand(NewSearchService()))
	rootCmd.AddCommand(NewCveCommand(NewSearchService()))

	for _, cliPlugin := range CliPlugins {
		rootCmd.AddCommand(cliPlugin.Command())
	}
}
