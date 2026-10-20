package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kunchenguid/treehouse/v3/internal/pool"
	"github.com/spf13/cobra"
)

func readAliasInput(path string, out any) (string, error) {
	if path == "" {
		return "", fmt.Errorf("explicit JSON input file required")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return "", fmt.Errorf("bounded regular JSON input required")
	}
	data, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil {
		return "", e
	}
	if len(data) > 1<<20 {
		return "", fmt.Errorf("input too large")
	}
	if e = pool.StrictAliasJSON(data, out); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

var reconcileAliasCmd = &cobra.Command{Use: "reconcile-alias", Short: "Preview or explicitly reconcile one authenticated alias duplicate", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return fmt.Errorf("select preview, apply, inspect or rollback") }}

func init() {
	rootCmd.AddCommand(reconcileAliasCmd)
	for _, mode := range []string{"preview", "apply", "inspect", "rollback"} {
		mode := mode
		var requestPath, previewPath, transaction, approval string
		c := &cobra.Command{Use: mode, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			if rootFlag != "" {
				return fmt.Errorf("reconciliation uses only the exact request pool; --root is forbidden")
			}
			var r pool.AliasRequest
			if _, e := readAliasInput(requestPath, &r); e != nil {
				return e
			}
			var output any
			var e error
			switch mode {
			case "preview":
				if previewPath != "" || transaction != "" || approval != "" {
					return fmt.Errorf("preview accepts only --request")
				}
				output, e = pool.PreviewAlias(r)
			case "apply":
				if transaction != "" {
					return fmt.Errorf("apply derives an exclusive transaction path")
				}
				var p pool.AliasPreview
				digest, err := readAliasInput(previewPath, &p)
				if err != nil {
					return err
				}
				if approval == "" || approval != digest {
					return fmt.Errorf("--approve-preview-sha256 must match the exact reviewed preview file")
				}
				output, e = pool.ApplyAlias(r, p, nil)
			default:
				if previewPath != "" || transaction == "" || approval != "" {
					return fmt.Errorf("inspect/rollback require --request and --transaction only")
				}
				output, e = pool.RecoverAlias(r, transaction, mode == "rollback", nil)
			}
			// An uncertain mutation needs a receipt even when the command fails.
			// Errors and receipts contain no raw state, keys or lease field dump.
			if result, ok := output.(pool.AliasResult); ok && result.Outcome != "" {
				if enc := json.NewEncoder(cmd.OutOrStdout()).Encode(result); enc != nil {
					return enc
				}
				return e
			}
			if e != nil {
				return e
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
		}}
		c.Flags().StringVar(&requestPath, "request", "", "Exact-target request JSON file")
		c.Flags().StringVar(&previewPath, "preview", "", "Fresh authenticated preview JSON file (apply only)")
		c.Flags().StringVar(&transaction, "transaction", "", "Exact transaction backup directory (inspect/rollback only)")
		c.Flags().StringVar(&approval, "approve-preview-sha256", "", "SHA256 of reviewed preview file (apply only)")
		reconcileAliasCmd.AddCommand(c)
	}
}
