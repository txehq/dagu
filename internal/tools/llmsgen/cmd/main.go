// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dagucloud/dagu/v2/internal/tools/llmsgen"
)

func main() {
	sourceDir := flag.String("source", filepath.Join("skills", "dagu"), "directory containing the bundled Dagu skill")
	sourcePrefix := flag.String("source-prefix", filepath.ToSlash(filepath.Join("skills", "dagu")), "source path prefix written into llms.txt")
	outputPath := flag.String("output", "llms.txt", "path to write")
	check := flag.Bool("check", false, "compare -output with the generated content and exit 1 if they differ; write nothing")
	flag.Parse()

	opts := llmsgen.Options{
		SourceDir:    *sourceDir,
		SourcePrefix: *sourcePrefix,
	}

	if *check {
		err := llmsgen.CheckFile(*outputPath, opts)
		if err == nil {
			fmt.Printf("%s matches %s\n", *outputPath, *sourceDir)
			return
		}
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, llmsgen.ErrStale) {
			fmt.Fprintf(os.Stderr, "Regenerate it with `make llms` and commit %s.\n", *outputPath)
		}
		os.Exit(1)
	}

	if err := llmsgen.WriteFile(*outputPath, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
