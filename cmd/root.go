package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/kunchenguid/treehouse/v3/internal/updater"
	"github.com/spf13/cobra"
)

var version = "dev"

var spawnBackgroundCheck = updater.SpawnBackgroundCheck

// rootFlag holds the value of the persistent --root flag. It overrides both the
// TREEHOUSE_ROOT environment variable and the configured root; see
// config.ResolveRoot for the full precedence.
var rootFlag string

func SetVersion(v string) {
	version = v
	rootCmd.Version = v
}

var rootCmd = &cobra.Command{
	Use:   "treehouse",
	Short: "Manage a pool of git worktrees for parallel AI agent workflows",
	Long: `Treehouse maintains a pool of reusable, pre-warmed git worktrees
so that multiple AI coding agents can work on the same repo in parallel.`,
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return getRunE(cmd, args)
	},
	PersistentPostRunE: func(*cobra.Command, []string) error {
		if admissionChildCheck != nil {
			return admissionChildCheck()
		}
		return nil
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := verifyAdmissionChild(cmd); err != nil {
			return err
		}
		// This explicit observation must not spawn a cache-writing updater.
		// Changed also covers an invalid empty path: refusals stay read-only.
		if isOutputOnlyCompletion(cmd) || cmd == launchAdmittedCmd || cmd.Parent() == reconcileAliasCmd || cmd == reconcileAliasCmd || (cmd == statusCmd && cmd.Flags().Changed("lease-path")) {
			return nil
		}
		// Skip update check for dev builds, Nix store installs (upgraded
		// through Nix, not `treehouse update`), the update command itself,
		// or when explicitly suppressed via env var.
		if version == "dev" || os.Getenv("TREEHOUSE_NO_UPDATE_CHECK") == "1" || runningFromNixStore() {
			return nil
		}
		if cmd.Name() == "update" {
			return nil
		}

		// Show cached update notice from a previous check
		if result := updater.ReadCache(version); result != nil && result.UpdateAvailable {
			yellow := color.New(color.FgYellow)
			yellow.Fprintf(os.Stderr, "A new version of treehouse is available: %s → %s\n", version, result.LatestVersion)
			yellow.Fprintln(os.Stderr, "Run \"treehouse update\" to update")
			fmt.Fprintln(os.Stderr)
		}

		// Spawn background check if cache is stale
		if updater.IsCacheStale(version) {
			_ = spawnBackgroundCheck(version)
		}

		return nil
	},
}

func init() {
	rootCmd.SetVersionTemplate(`{{.Version}}` + "\n")
	rootCmd.PersistentFlags().StringVar(&rootFlag, "root", "",
		"Worktree root directory, overriding TREEHOUSE_ROOT and config; relative paths (e.g. \".\" for an in-project pool) resolve from the repo root")
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
