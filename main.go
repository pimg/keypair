package main

import (
	"fmt"
	"keypair/csr"
	"keypair/keypair"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
)

var (
	curve              keypair.Curve
	publicKeyFilename  string
	privateKeyFilename string
	withCSR            bool
	csrArgs            csr.CSRArgs
	csrFilename        string
)

func main() {
	accessible, _ := strconv.ParseBool(os.Getenv("ACCESSIBLE"))
	confirm := false
	withCSR = false
	defaultPublicKeyFilename := "pub.pem"
	defaultPrivateKeyFilename := "priv.key"
	defaultCSRFilename := "csr.pem"
	csrArgs = csr.CSRArgs{}
	form := huh.NewForm(
		huh.NewGroup(huh.NewNote().
			Title("Generate a Keypair").
			Description("Would you like to generate a new keypair\n\nWe only support EC keypairs").
			Next(true).
			NextLabel("Next"),
		),

		huh.NewGroup(
			huh.NewSelect[string]().
				Options(huh.NewOptions(keypair.ED25519.String(), keypair.P256.String(), keypair.P384.String(), keypair.P521.String())...).
				Title("Curve").
				Description("What curve would you like to use").
				Value((*string)(&curve)),

			huh.NewInput().
				Title("Private key filename").
				Value(&privateKeyFilename).
				Description("What is the private key filename").
				Placeholder("priv.key"),

			huh.NewInput().
				Title("Public key filename").
				Value(&publicKeyFilename).
				Description("What is the public key filename").
				Placeholder("pub.pem"),

			huh.NewConfirm().
				Title("CSR").
				Description("Do you want to generate a CSR?").
				Value(&withCSR).
				Affirmative("Yes").
				Negative("No"),
		),

		huh.NewGroup(
			huh.NewNote().Title("Generating a CSR").Description("You are about to generate a CSR"),

			huh.NewInput().
				Title("CN").
				Value(&csrArgs.CN).
				Description("Common Name").
				Placeholder("enter CN..."),

			huh.NewInput().
				Title("Email").
				Value(&csrArgs.Email).
				Description("Email").
				Placeholder("enter email..."),

			huh.NewInput().
				Title("C").
				Value(&csrArgs.Country).
				Description("Country").
				Placeholder("enter country..."),

			huh.NewInput().
				Title("S").
				Value(&csrArgs.State).
				Description("State").
				Placeholder("enter state..."),

			huh.NewInput().
				Title("L").
				Value(&csrArgs.Locality).
				Description("Locality").
				Placeholder("enter locality..."),

			huh.NewInput().
				Title("O").
				Value(&csrArgs.Organization).
				Description("Organisation").
				Placeholder("enter organisation..."),

			huh.NewInput().
				Title("OU").
				Value(&csrArgs.OU).
				Description("Organisation Unit").
				Placeholder("enter organisation unit..."),

			huh.NewInput().
				Title("CSR filename").
				Value(&csrFilename).
				Description("What is the CSR filename").
				Placeholder("csr.pem"),
		).WithHide(withCSR),

		// TODO refactor confirm to have multiple confirms for keypair and csr
		huh.NewGroup(
			huh.NewConfirm().
				Title("Confirm").
				Description(fmt.Sprintf("Generating keypair using: \nCurve: %s\n, Public Key: %s\nPrivate Key: %s", curve, defaultIfEmpty(publicKeyFilename, defaultPublicKeyFilename), defaultIfEmpty(privateKeyFilename, defaultPrivateKeyFilename))).
				Value(&confirm).
				Affirmative("OK").
				Negative("Cancel"),
		),
	).WithAccessible(accessible)

	err := form.Run()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	if !confirm {
		fmt.Println("Operation cancelled")
		os.Exit(0)
	}

	privateKeyFilename = defaultIfEmpty(privateKeyFilename, defaultPrivateKeyFilename)
	publicKeyFilename = defaultIfEmpty(publicKeyFilename, defaultPublicKeyFilename)
	csrFilename = defaultIfEmpty(csrFilename, defaultCSRFilename)

	keyPairAction := func() {
		err = generateKeypair(keypair.ECOpts{Curve: curve})
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	_ = spinner.New().Title("Generating Keypair...").Accessible(accessible).Action(keyPairAction).Run()

	err = summary()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func defaultIfEmpty(value, defaultVal string) string {
	if value == "" {
		return defaultVal
	}

	return value
}

func generateKeypair(opts keypair.ECOpts) error {
	publicKey, privateKey, err := keypair.GenerateECKeyPair(opts)
	if err != nil {
		return err
	}

	publicKeyBytes, privateKeyBytes, err := keypair.EncodeToPEM(publicKey, privateKey)
	if err != nil {
		return err
	}

	err = os.WriteFile(publicKeyFilename, publicKeyBytes, 0o644)
	if err != nil {
		return err
	}

	err = os.WriteFile(privateKeyFilename, privateKeyBytes, 0o640)
	if err != nil {
		return err
	}

	if withCSR {
		csrArgs.Curve = opts.Curve
		csrArgs.PrivateKey = privateKey
		rawCSR, err := csr.GenerateCSR(csrArgs)
		if err != nil {
			return err
		}

		csrPem := csr.EncodeToPEM(rawCSR)

		err = os.WriteFile(csrFilename, csrPem, 0o644)
		if err != nil {
			return err
		}
	}

	return nil
}

// TODO better levarage the strings.Builder to add optional CSR details
func summary() error {
	var sb strings.Builder

	keyword := func(s string) string {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Render(s)
	}
	_, err := fmt.Fprintf(&sb, `

With curve: %s

save to disk:
	private_key: %s
	public_key: %s

With CRS: %t

		`,
		keyword(curve.String()), keyword(privateKeyFilename), keyword(publicKeyFilename), withCSR)
	if err != nil {
		return err
	}

	fmt.Println(
		lipgloss.NewStyle().
			Width(40).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2).
			Render(sb.String()),
	)

	return nil
}
