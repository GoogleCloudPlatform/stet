// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This binary is the main entrypoint for the STET command line tool.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"flag"
	"github.com/GoogleCloudPlatform/stet/client"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	glog "github.com/golang/glog"
	"github.com/google/subcommands"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

const (
	// The default name for the STET configuration file.
	defaultConfigName string = "stet.yaml"
	// The default permissions (u=rw,g=r,o=r)for new files created by STET, prior to unmask.
	defaultFilePerms os.FileMode = 0644
)

// These variables can be overridden by ldflags, as GoReleaser does when
// publishing new releases, to provide more information about the build.
var commit string
var date string
var version string

// First step to an atomic file write for output files.
// Creates and returns a temporary file. finalizeOutput (below) should be called after the necessary
// contents are written to the temporary file.
func setupOutputFile(outputPath string) (*os.File, error) {
	if outputPath == "" {
		return nil, errors.New("no output file path specified")
	}

	// Create a temporary file. For atomicity, it will be renamed to the proper output file name once
	// at the end of the workflow.
	parent := filepath.Dir(outputPath)
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		if err := os.MkdirAll(parent, 0755); err != nil {
			return nil, err
		}
	}

	f, err := ioutil.TempFile(parent, "")
	if err != nil {
		return nil, fmt.Errorf("Failed to create temporary file for write at %v: %v", parent, err.Error())
	}

	if err := os.Chmod(f.Name(), defaultFilePerms); err != nil {
		os.Remove(f.Name())
		return nil, err
	}

	return f, nil
}

// Second step to an atomic file write for output files.
// Should be called after the necessary content has been written to the temporary file returned by
// setupOutput (above). Renames the temporary file to outputPath.
func finalizeOutputFile(outputPath string, outFile *os.File) error {
	if outputPath == "" {
		return errors.New("no output file path specified")
	}

	if outFile == nil {
		return fmt.Errorf("no output file specified")
	}

	// Commit file contents to stable storage before proceeding.
	if err := outFile.Sync(); err != nil {
		return fmt.Errorf("Failed to sync temporary file: %v", err.Error())
	}

	if err := outFile.Close(); err != nil {
		return fmt.Errorf("Failed to close temporary file: %v", err.Error())
	}

	// Rename to provided output.
	if err := os.Rename(outFile.Name(), outputPath); err != nil {
		return fmt.Errorf("Failed to rename temporary file to output: %v", err.Error())
	}

	return nil
}

// encryptCmd handles CLI options for the encryption command.
type encryptCmd struct {
	configFile         string
	blobID             string
	insecureSkipVerify bool
	quiet              bool
}

func (*encryptCmd) Name() string { return "encrypt" }
func (*encryptCmd) Synopsis() string {
	return "encrypts plaintext according to the given config"
}
func (*encryptCmd) Usage() string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		glog.Errorf("Failed to get config directory location: %v", err.Error())
	}

	return fmt.Sprintf(`Usage: stet encrypt [--config-file=<config_file>] [--blob-id=<blob_id>] <plaintext_file> <encrypted_file>

Examples:
  Encrypt a file using STET, using %s for configuration:
    $ stet encrypt plaintext.txt ciphertext.txt

  Encrypt with the given blob ID and specific configuration file:
    $ stet encrypt --config-file="my_config.yaml" --blob-id="foobar" plaintext.txt ciphertext.txt

  Encrypt with plaintext input from stdin:
    $ stet encrypt - ciphertext.txt < plaintext.txt

	Encrypt with ciphertext output written to stdout:
    $ stet encrypt plaintext.txt - > ciphertext.txt

  Encrypt with input from stdin and output to stdout:
	 $ my-application | stet encrypt - - | my-other-application

Flags:
`, fmt.Sprintf("%s/%s", cfgDir, defaultConfigName))
	// The flags are automatically printed after the returned text.
}
func (e *encryptCmd) SetFlags(f *flag.FlagSet) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		glog.Errorf("Failed to get config directory location: %v", err.Error())
	}

	configFilePath := fmt.Sprintf("%s/%s", cfgDir, defaultConfigName)
	f.StringVar(&e.configFile, "config-file", configFilePath, "Path to a StetConfig YAML file. Optional.")
	f.StringVar(&e.blobID, "blob-id", "", "The blob ID to assign to the encrypted blob. Optional.")
	f.BoolVar(&e.insecureSkipVerify, "insecure-skip-verify", false, "Disable certificate check for inner TLS session.")
	f.BoolVar(&e.quiet, "quiet", false, "Suppress logging output.")
}

func (e *encryptCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	yamlBytes, err := os.ReadFile(e.configFile)
	if err != nil {
		glog.Errorf("Failed to read config file: %v", err.Error())
		return subcommands.ExitFailure
	}

	jsonBytes, err := yaml.YAMLToJSON(yamlBytes)
	if err != nil {
		glog.Errorf("Failed to convert config YAML to JSON: %v", err.Error())
		return subcommands.ExitFailure
	}

	stetConfig := &configpb.StetConfig{}
	if err := protojson.Unmarshal(jsonBytes, stetConfig); err != nil {
		glog.Errorf("Failed to unmarshal StetConfig: %v", err.Error())
		return subcommands.ExitFailure
	}

	if stetConfig.GetEncryptConfig() == nil {
		glog.Errorf("No EncryptConfig stanza found in config file")
		return subcommands.ExitFailure
	}

	if f.NArg() < 2 {
		glog.Errorf("Not enough arguments (expected plaintext file and encrypted file)")
		return subcommands.ExitFailure
	}

	var inFile io.Reader

	if f.Arg(0) == "-" {
		// Read input from stdin.
		inFile = os.Stdin
	} else {
		inFile, err = os.Open(f.Arg(0))
		if err != nil {
			glog.Errorf("Failed to open plaintext file: %v", err.Error())
			return subcommands.ExitFailure
		}
	}

	var outFile *os.File
	var logFile *os.File

	outputArg := f.Arg(1)
	if outputArg == "-" {
		// If output goes to stdout, use stderr for logging.
		outFile = os.Stdout
		logFile = os.Stderr
	} else {
		// For atomicity, create a temp file to write to.
		outFile, err = setupOutputFile(outputArg)
		if err != nil {
			glog.Errorf("Failed to setup output %v: %v", outputArg, err.Error())
			return subcommands.ExitFailure
		}
		defer os.Remove(outFile.Name())

		logFile = os.Stdout
	}

	// Initialize StetClient and encrypt plaintext.
	c := client.StetClient{
		InsecureSkipVerify: e.insecureSkipVerify,
		Version:            version,
	}

	md, err := c.Encrypt(ctx, inFile, outFile, stetConfig, e.blobID)
	if err != nil {
		glog.Errorf("Failed to encrypt plaintext: %v", err.Error())
		return subcommands.ExitFailure
	}

	// If writing to a file (not stdout), rename the temp output file to the provided argument.
	if outputArg != "-" {
		if err := finalizeOutputFile(outputArg, outFile); err != nil {
			glog.Errorf("Failed to finalize output: %v", err.Error())
			return subcommands.ExitFailure
		}
	}

	if !e.quiet {
		if outputArg == "-" {
			outputArg = os.Stdout.Name()
		}

		logFile.WriteString(fmt.Sprintln("Wrote encrypted data to", outputArg))

		// Debug information to guard against authorship attacks.
		logFile.WriteString(fmt.Sprintln("Blob ID of encrypted data:", md.BlobID))
		if len(md.KeyUris) > 0 {
			logFile.WriteString(fmt.Sprintln("Used these key URIs:", md.KeyUris))
		}
	}

	return subcommands.ExitSuccess
}

// decryptCmd handles CLI options for the decryption command.
type decryptCmd struct {
	configFile         string
	blobID             string
	insecureSkipVerify bool
	quiet              bool
}

func (*decryptCmd) Name() string { return "decrypt" }
func (*decryptCmd) Synopsis() string {
	return "decrypts blob and metadata according to the given config"
}
func (*decryptCmd) Usage() string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		glog.Errorf("Failed to get config directory location: %v", err.Error())
	}

	return fmt.Sprintf(`Usage: stet decrypt [--config-file=<config_file>] [--blob-id=<blob_id>] <ciphertext_file> <plaintext_file>

Example:
  Decrypt a file using STET, using %s for configuration:
    $ stet decrypt ciphertext.txt plaintext.txt
    Wrote plaintext to plaintext.txt
    Blob ID of decrypted data: ...
    Used these key URIs: [...]

  Decrypt with the given blob ID and a specific configuration file:
    $ stet decrypt --config-file="my_config.yaml" --blob-id="foobar" ciphertext.txt plaintext.txt
    Wrote plaintext to plaintext.txt
    Blob ID of decrypted data: foobar
    Used these key URIs: [...]

  Decrypt with ciphertext input from stdin:
    $ stet decrypt - plaintext.txt < ciphertext.txt
    Wrote plaintext to plaintext.txt
    Blob ID of decrypted data: ...
    Used these key URIs: [...]

	Decrypt with plaintext outputted to stdout:
    $ stet decrypt ciphertext.txt - > plaintext.txt
		Wrote plaintext to stdout.
    Blob ID of decrypted data: ...
    Used these key URIs: [...]

  Decrypt with input from stdin and output to stdout:
	  $ my-application | stet decrypt - - | my-other-application
    Wrote plaintext to stdout.
    Blob ID of decrypted data: ...
    Used these key URIs: [...]

Flags:
`, fmt.Sprintf("%s/%s", cfgDir, defaultConfigName))
}
func (d *decryptCmd) SetFlags(f *flag.FlagSet) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		glog.Errorf("Failed to get config directory location: %v", err.Error())
	}

	configFilePath := fmt.Sprintf("%s/%s", cfgDir, defaultConfigName)
	f.StringVar(&d.configFile, "config-file", configFilePath, "Path to a StetConfig YAML file. Optional.")
	f.StringVar(&d.blobID, "blob-id", "", "The blob ID to validate the decryption against. Optional.")
	f.BoolVar(&d.insecureSkipVerify, "insecure-skip-verify", false, "Disable certificate check for inner TLS session.")
	f.BoolVar(&d.quiet, "quiet", false, "Suppress logging output.")
}

func (d *decryptCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	yamlBytes, err := os.ReadFile(d.configFile)
	if err != nil {
		glog.Errorf("Failed to read config file: %v", err.Error())
		return subcommands.ExitFailure
	}

	jsonBytes, err := yaml.YAMLToJSON(yamlBytes)
	if err != nil {
		glog.Errorf("Failed to convert config YAML to JSON: %v", err.Error())
		return subcommands.ExitFailure
	}

	stetConfig := &configpb.StetConfig{}
	if err := protojson.Unmarshal(jsonBytes, stetConfig); err != nil {
		glog.Errorf("Failed to unmarshal StetConfig: %v", err.Error())
		return subcommands.ExitFailure
	}

	if stetConfig.GetDecryptConfig() == nil {
		glog.Errorf("No DecryptConfig stanza found in config file")
		return subcommands.ExitFailure
	}

	if f.NArg() < 2 {
		glog.Errorf("Not enough arguments (expected encrypted file and plaintext file)")
		return subcommands.ExitFailure
	}

	var inFile io.Reader

	if f.Arg(0) == "-" {
		// Read input from stdin.
		inFile = os.Stdin
	} else {
		inFile, err = os.Open(f.Arg(0))
		if err != nil {
			glog.Errorf("Failed to open ciphertext file: %v", err.Error())
			return subcommands.ExitFailure
		}
	}

	var outFile *os.File
	var logFile *os.File

	outputArg := f.Arg(1)
	if outputArg == "-" {
		// If output goes to stdout, use stderr for logging.
		outFile = os.Stdout
		logFile = os.Stderr
	} else {
		outFile, err = setupOutputFile(outputArg)
		if err != nil {
			glog.Errorf("Failed to setup output %v: %v", outputArg, err.Error())
			return subcommands.ExitFailure
		}
		defer os.Remove(outFile.Name())

		logFile = os.Stdout
	}

	// Initialize StetClient and decrypt plaintext.
	c := client.StetClient{
		InsecureSkipVerify: d.insecureSkipVerify,
		Version:            version,
	}

	md, err := c.Decrypt(ctx, inFile, outFile, stetConfig)
	if err != nil {
		glog.Errorf("Failed to decrypt ciphertext: %v", err.Error())
		return subcommands.ExitFailure
	}

	// If writing to a file (not stdout), there is an extra step.
	if outputArg != "-" {
		if err := finalizeOutputFile(outputArg, outFile); err != nil {
			glog.Errorf("Failed to write to output file: %v", err.Error())
			return subcommands.ExitFailure
		}
	}

	if !d.quiet {
		if outputArg == "-" {
			outputArg = os.Stdout.Name()
		}

		logFile.WriteString(fmt.Sprintln("Wrote plaintext to", outputArg))

		// Debug information to guard against authorship attacks.
		logFile.WriteString(fmt.Sprintln("Blob ID of decrypted data:", md.BlobID))
		if len(md.KeyUris) > 0 {
			logFile.WriteString(fmt.Sprintln("Used these key URIs:", md.KeyUris))
		}
	}

	return subcommands.ExitSuccess
}

// versionCmd handles CLI options for the version command.
type versionCmd struct{}

func (*versionCmd) Name() string           { return "version" }
func (*versionCmd) Synopsis() string       { return "prints the current version" }
func (*versionCmd) Usage() string          { return "Usage: stet version" }
func (*versionCmd) SetFlags(*flag.FlagSet) {}
func (*versionCmd) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	if version == "" {
		fmt.Println("Version: development")
	} else {
		fmt.Printf("Version: %v (%v, build date: %v)\n", version, commit, date)
	}
	return subcommands.ExitSuccess
}

func main() {
	// If effective UID is 0 and real UID != 0, we invoked as user but need to deescalate.
	euid := syscall.Geteuid()
	ruid := syscall.Getuid()
	if euid == 0 && ruid != 0 {
		// This means we are root. Swap the real and effective UIDs to de-escalate until
		// we need to re-escalate (as part of generating attestations).
		err := syscall.Setreuid(euid, ruid)
		if err != nil {
			glog.Fatalf("Failed to deescalate from root to user: %s", err.Error())
		}
	}

	flag.Parse()

	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(&encryptCmd{}, "")
	subcommands.Register(&decryptCmd{}, "")
	subcommands.Register(&versionCmd{}, "")

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
