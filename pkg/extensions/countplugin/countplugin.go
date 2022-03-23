/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package countplugin

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	. "zotregistry.io/zot/pkg/cli/cliplugin"
	
)

// implement the public interface from zot
type CountPlugin struct {
}

func (countP CountPlugin) Command() *cobra.Command {
	countCmd := &cobra.Command{
		Use:   "count",
		Short: "Counts untill the number you give it.",
		Long: `A longer description that spans multiple lines and likely contains examples
	and usage of using your command. For example:
	
	Cobra is a CLI library for Go that empowers applications.
	This application is a tool to generate the needed files
	to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				fmt.Println("Give a number.")
				return nil
			}
			n, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Println(-1)
				return nil
			}

			for i := 0; i < n; i++ {
				fmt.Println(i)
			}

			return nil
		},
	}

	return countCmd
}

func init() {
	CliPlugins["count-plugin"] = CountPlugin{}
}
