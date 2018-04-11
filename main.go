package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"



	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/yaml.v2"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"github.com/magiconair/properties"
	"strconv"
)

var (
	configFilePath = fmt.Sprintf("%s/.aws/roles", os.Getenv("HOME"))
	roleArnRe      = regexp.MustCompile(`^arn:aws:iam::(.+):role/([^/]+)(/.+)?$`)
    mfaSercret     = ""
)

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}


func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <role> [<command> <args...>]\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	flag.Usage = usage
}

func defaultFormat() string {
	var shell = os.Getenv("SHELL")

	switch runtime.GOOS {
	case "windows":
		if os.Getenv("SHELL") == "" {
			return "powershell"
		}
		fallthrough
	default:
		if strings.HasSuffix(shell, "fish") {
			return "fish"
		}
		return "bash"
	}
}

func ParseInt64(value string) int64 {
	if len(value) == 0 {
		return 0
	}
	parsed, err := strconv.Atoi(value[:len(value)-1])
	if err != nil {
		return 0
	}
	return int64(parsed)
}

func main() {
	p := properties.MustLoadFile("${HOME}/.assume-role.properties", properties.UTF8)

	mfaSercretProperty, ok := p.Get("mfa.secret")
	inputNoSpaces := strings.Replace(mfaSercretProperty, " ", "", -1)
	mfaSercret = strings.ToUpper(inputNoSpaces)

	if !ok {
		fmt.Printf("Please ensure you have mfa.secret property defined in ${HOME}/.assume-role.properties")
		os.Exit(1)
	}

	durationProperty := p.GetInt("duration", 1)
	duration := time.Duration(durationProperty)  * time.Hour

	format := p.GetString("format", defaultFormat())

	flag.Parse()
	argv := flag.Args()
	if len(argv) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	stscreds.DefaultDuration = duration

	role := argv[0]
	args := argv[1:]

	// Load credentials from configFilePath if it exists, else use regular AWS config
	var creds *credentials.Value
	var err error
	if roleArnRe.MatchString(role) {
		creds, err = assumeRole(role, "", duration)
	} else if _, err = os.Stat(configFilePath); err == nil {
		fmt.Fprintf(os.Stderr, "WARNING: using deprecated role file (%s), switch to config file"+
			" (https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html)\n",
			configFilePath)
		config, err := loadConfig()
		must(err)

		roleConfig, ok := config[role]
		if !ok {
			must(fmt.Errorf("%s not in %s", role, configFilePath))
		}

		creds, err = assumeRole(roleConfig.Role, roleConfig.MFA, duration)
	} else {
		creds, err = assumeProfile(role)
	}

	must(err)

	if len(args) == 0 {
		switch format {
		case "powershell":
			printPowerShellCredentials(role, creds)
		case "bash":
			printCredentials(role, creds)
		case "fish":
			printFishCredentials(role, creds)
		default:
			flag.Usage()
			os.Exit(1)
		}
		return
	}

	err = execWithCredentials(role, args, creds)
	must(err)
}

func execWithCredentials(role string, argv []string, creds *credentials.Value) error {
	argv0, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}

	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
	os.Setenv("ASSUMED_ROLE", role)

	env := os.Environ()
	return syscall.Exec(argv0, argv, env)
}

// printCredentials prints the credentials in a way that can easily be sourced
// with bash.
func printCredentials(role string, creds *credentials.Value) {
	fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("export AWS_SECURITY_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("export ASSUMED_ROLE=\"%s\"\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# eval $(%s)\n", strings.Join(os.Args, " "))
}

// printFishCredentials prints the credentials in a way that can easily be sourced
// with fish.
func printFishCredentials(role string, creds *credentials.Value) {
	fmt.Printf("set -gx AWS_ACCESS_KEY_ID \"%s\";\n", creds.AccessKeyID)
	fmt.Printf("set -gx AWS_SECRET_ACCESS_KEY \"%s\";\n", creds.SecretAccessKey)
	fmt.Printf("set -gx AWS_SESSION_TOKEN \"%s\";\n", creds.SessionToken)
	fmt.Printf("set -gx AWS_SECURITY_TOKEN \"%s\";\n", creds.SessionToken)
	fmt.Printf("set -gx ASSUMED_ROLE \"%s\";\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# eval (%s)\n", strings.Join(os.Args, " "))
}

// printPowerShellCredentials prints the credentials in a way that can easily be sourced
// with Windows powershell using Invoke-Expression.
func printPowerShellCredentials(role string, creds *credentials.Value) {
	fmt.Printf("$env:AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("$env:AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("$env:AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("$env:AWS_SECURITY_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("$env:ASSUMED_ROLE=\"%s\"\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# %s | Invoke-Expression \n", strings.Join(os.Args, " "))
}

// assumeProfile assumes the named profile which must exist in ~/.aws/config
// (https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) and returns the temporary STS
// credentials.
func assumeProfile(profile string) (*credentials.Value, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile:                 profile,
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: getTokenCode,
	}))

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, err
	}
	return &creds, nil
}

// assumeRole assumes the given role and returns the temporary STS credentials.
func assumeRole(role, mfa string, duration time.Duration) (*credentials.Value, error) {
	sess := session.Must(session.NewSession())

	svc := sts.New(sess)

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(role),
		RoleSessionName: aws.String("cli"),
		DurationSeconds: aws.Int64(int64(duration / time.Second)),
	}
	if mfa != "" {
		params.SerialNumber = aws.String(mfa)
		token, err := getTokenCode()
		if err != nil {
			return nil, err
		}
		params.TokenCode = aws.String(token)
	}

	var resp *sts.AssumeRoleOutput
	var err error
	if mfa != "" {
		for i := 0; i < 5; i++ {
			resp, err = svc.AssumeRole(params)
			if err == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
	} else {
		resp, err = svc.AssumeRole(params)
	}

	if err != nil {
		return nil, err
	}

	var creds credentials.Value
	creds.AccessKeyID = *resp.Credentials.AccessKeyId
	creds.SecretAccessKey = *resp.Credentials.SecretAccessKey
	creds.SessionToken = *resp.Credentials.SessionToken

	return &creds, nil
}

type roleConfig struct {
	Role string `yaml:"role"`
	MFA  string `yaml:"mfa"`
}

type config map[string]roleConfig

// getTokenCode reads the MFA token from Stdin.
func getTokenCode() (string, error) {
	key, err := base32.StdEncoding.DecodeString(mfaSercret)
	epochSeconds := time.Now().Unix()
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))
	return fmt.Sprint(pwd), err
}

// loadConfig loads the ~/.aws/roles file.
func loadConfig() (config, error) {
	raw, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	roleConfig := make(config)
	return roleConfig, yaml.Unmarshal(raw, &roleConfig)
}

func must(err error) {
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Errors are already on Stderr.
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
