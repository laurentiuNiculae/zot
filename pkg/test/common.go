package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	notconfig "github.com/notaryproject/notation-go/config"
	"github.com/notaryproject/notation-go/dir"
	notreg "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/notation-go/verifier"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/project-zot/mockoidc"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	zLog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	stypes "zotregistry.io/zot/pkg/storage/types"
	testc "zotregistry.io/zot/pkg/test/common"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	BaseURL       = "http://127.0.0.1:%s"
	BaseSecureURL = "https://127.0.0.1:%s"
	SleepTime     = 100 * time.Millisecond
)

var (
	ErrSignatureVerification = errors.New("signature verification failed")
	ErrAlreadyExists         = errors.New("already exists")
	ErrKeyNotFound           = errors.New("key not found")
)

var NotationPathLock = new(sync.Mutex) //nolint: gochecknoglobals

// which: manifest, config, layer
func GetTestBlobDigest(image, which string) godigest.Digest {
	prePath := "../test/data"

	for _, err := os.Stat(prePath); err != nil; _, err = os.Stat(prePath) {
		prePath = "../" + prePath
	}

	imgPath := path.Join(prePath, image)
	manifest, config, layer := GetOciLayoutDigests(imgPath)

	switch which {
	case "manifest":
		return manifest
	case "config":
		return config
	case "layer":
		return layer
	}

	return ""
}

func MakeHtpasswdFile() string {
	// bcrypt(username="test", passwd="test")
	content := "test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n"

	return MakeHtpasswdFileFromString(content)
}

func GetCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
}

func MakeHtpasswdFileFromString(fileContent string) string {
	htpasswdFile, err := os.CreateTemp("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte(fileContent)
	if err := os.WriteFile(htpasswdFile.Name(), content, 0o600); err != nil { //nolint:gomnd
		panic(err)
	}

	return htpasswdFile.Name()
}

type Controller interface {
	Init(ctx context.Context) error
	Run(ctx context.Context) error
	Shutdown()
	GetPort() int
}

type ControllerManager struct {
	controller Controller
	// used to stop background tasks(goroutines)
	cancelRoutinesFunc context.CancelFunc
}

func (cm *ControllerManager) RunServer(ctx context.Context) {
	// Useful to be able to call in the same goroutine for testing purposes
	if err := cm.controller.Run(ctx); !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func (cm *ControllerManager) StartServer() {
	ctx, cancel := context.WithCancel(context.Background())
	cm.cancelRoutinesFunc = cancel

	if err := cm.controller.Init(ctx); err != nil {
		panic(err)
	}

	go func() {
		cm.RunServer(ctx)
	}()
}

func (cm *ControllerManager) StopServer() {
	// stop background tasks
	if cm.cancelRoutinesFunc != nil {
		cm.cancelRoutinesFunc()
	}

	cm.controller.Shutdown()
}

func (cm *ControllerManager) WaitServerToBeReady(port string) {
	url := testc.GetBaseURL(port)
	WaitTillServerReady(url)
}

func (cm *ControllerManager) StartAndWait(port string) {
	cm.StartServer()

	url := testc.GetBaseURL(port)
	WaitTillServerReady(url)
}

func NewControllerManager(controller Controller) ControllerManager {
	cm := ControllerManager{
		controller: controller,
	}

	return cm
}

func WaitTillServerReady(url string) {
	for {
		_, err := resty.R().Get(url)
		if err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

func WaitTillTrivyDBDownloadStarted(rootDir string) {
	for {
		if _, err := os.Stat(path.Join(rootDir, "_trivy", "db", "trivy.db")); err == nil {
			break
		}

		time.Sleep(SleepTime)
	}
}

// Adapted from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
func RandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

	ret := make([]byte, n)

	for count := 0; count < n; count++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}

		ret[count] = letters[num.Int64()]
	}

	return string(ret)
}

func GetRandomImageConfig() ([]byte, godigest.Digest) {
	const maxLen = 16

	randomAuthor := RandomString(maxLen)

	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: randomAuthor,
	}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}

// TODO: Change the tests to remove this
func GetOciLayoutDigests(imagePath string) (godigest.Digest, godigest.Digest, godigest.Digest) {
	var (
		manifestDigest godigest.Digest
		configDigest   godigest.Digest
		layerDigest    godigest.Digest
	)

	oci, err := umoci.OpenLayout(imagePath)
	if err != nil {
		panic(fmt.Errorf("error opening layout at '%s' : %w", imagePath, err))
	}

	defer oci.Close()

	ctxUmoci := context.Background()

	index, err := oci.GetIndex(ctxUmoci)
	if err != nil {
		panic(err)
	}

	for _, manifest := range index.Manifests {
		manifestDigest = manifest.Digest

		manifestBlob, err := oci.GetBlob(ctxUmoci, manifest.Digest)
		if err != nil {
			panic(err)
		}

		manifestBuf, err := io.ReadAll(manifestBlob)
		if err != nil {
			panic(err)
		}

		var manifest ispec.Manifest

		err = json.Unmarshal(manifestBuf, &manifest)
		if err != nil {
			panic(err)
		}

		configDigest = manifest.Config.Digest

		for _, layer := range manifest.Layers {
			layerDigest = layer.Digest
		}
	}

	return manifestDigest, configDigest, layerDigest
}

func ReadLogFileAndSearchString(logPath string, stringToMatch string, timeout time.Duration) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Contains(string(content), stringToMatch) {
				return true, nil
			}
		}
	}
}

func ReadLogFileAndCountStringOccurence(logPath string, stringToMatch string,
	timeout time.Duration, count int,
) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Count(string(content), stringToMatch) >= count {
				return true, nil
			}
		}
	}
}

func CopyFile(sourceFilePath, destFilePath string) error {
	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	sourceFile, err := os.Open(sourceFilePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return nil
}

func LoadNotationPath(tdir string) {
	dir.UserConfigDir = filepath.Join(tdir, "notation")

	// set user libexec
	dir.UserLibexecDir = dir.UserConfigDir
}

func GenerateNotationCerts(tdir string, certName string) error {
	// generate RSA private key
	bits := 2048

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	rsaCertTuple := testhelper.GetRSASelfSignedCertTupleWithPK(key, "cert")

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCertTuple.Cert.Raw})

	// write private key
	relativeKeyPath, relativeCertPath := dir.LocalKeyPath(certName)

	configFS := dir.ConfigFS()

	keyPath, err := configFS.SysPath(relativeKeyPath)
	if err != nil {
		return err
	}

	certPath, err := configFS.SysPath(relativeCertPath)
	if err != nil {
		return err
	}

	if err := WriteFileWithPermission(keyPath, keyPEM, 0o600, false); err != nil { //nolint:gomnd
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// write self-signed certificate
	if err := WriteFileWithPermission(certPath, certBytes, 0o644, false); err != nil { //nolint:gomnd
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	signingKeys, err := notconfig.LoadSigningKeys()
	if err != nil {
		return err
	}

	keySuite := notconfig.KeySuite{
		Name: certName,
		X509KeyPair: &notconfig.X509KeyPair{
			KeyPath:         keyPath,
			CertificatePath: certPath,
		},
	}

	// addKeyToSigningKeys
	if Contains(signingKeys.Keys, keySuite.Name) {
		return ErrAlreadyExists
	}

	signingKeys.Keys = append(signingKeys.Keys, keySuite)

	// Add to the trust store
	trustStorePath := path.Join(tdir, fmt.Sprintf("notation/truststore/x509/ca/%s", certName))

	if _, err := os.Stat(filepath.Join(trustStorePath, filepath.Base(certPath))); err == nil {
		return ErrAlreadyExists
	}

	if err := os.MkdirAll(trustStorePath, 0o755); err != nil { //nolint:gomnd
		return fmt.Errorf("GenerateNotationCerts os.MkdirAll failed: %w", err)
	}

	trustCertPath := path.Join(trustStorePath, fmt.Sprintf("%s%s", certName, dir.LocalCertificateExtension))

	err = CopyFile(certPath, trustCertPath)
	if err != nil {
		return err
	}

	// Save to the SigningKeys.json
	if err := signingKeys.Save(); err != nil {
		return err
	}

	return nil
}

func SignWithNotation(keyName string, reference string, tdir string) error {
	ctx := context.TODO()

	// getSigner
	var newSigner notation.Signer

	mediaType := jws.MediaTypeEnvelope

	// ResolveKey
	signingKeys, err := LoadNotationSigningkeys(tdir)
	if err != nil {
		return err
	}

	idx := Index(signingKeys.Keys, keyName)
	if idx < 0 {
		return ErrKeyNotFound
	}

	key := signingKeys.Keys[idx]

	if key.X509KeyPair != nil {
		newSigner, err = signer.NewFromFiles(key.X509KeyPair.KeyPath, key.X509KeyPair.CertificatePath)
		if err != nil {
			return err
		}
	}

	// prepareSigningContent
	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	plainHTTP := true

	// Resolve referance
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repositoryOpts := notreg.RepositoryOptions{}

	sigRepo := notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	sigOpts := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: mediaType,
			PluginConfig:       map[string]string{},
		},
		ArtifactReference: ref.String(),
	}

	_, err = notation.Sign(ctx, newSigner, sigRepo, sigOpts)
	if err != nil {
		return err
	}

	return nil
}

func VerifyWithNotation(reference string, tdir string) error {
	// check if trustpolicy.json exists
	trustpolicyPath := path.Join(tdir, "notation/trustpolicy.json")

	if _, err := os.Stat(trustpolicyPath); errors.Is(err, os.ErrNotExist) {
		trustPolicy := `
			{
				"version": "1.0",
				"trustPolicies": [
					{
						"name": "good",
						"registryScopes": [ "*" ],
						"signatureVerification": {
							"level" : "audit" 
						},
						"trustStores": ["ca:good"],
						"trustedIdentities": [
							"*"
						]
					}
				]
			}`

		file, err := os.Create(trustpolicyPath)
		if err != nil {
			return err
		}

		defer file.Close()

		_, err = file.WriteString(trustPolicy)
		if err != nil {
			return err
		}
	}

	// start verifying signatures
	ctx := context.TODO()

	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	plainHTTP := true

	// Resolve referance
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repositoryOpts := notreg.RepositoryOptions{}

	repo := notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	manifestDesc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return err
	}

	if err := ref.ValidateReferenceAsDigest(); err != nil {
		ref.Reference = manifestDesc.Digest.String()
	}

	// getVerifier
	newVerifier, err := verifier.NewFromConfig()
	if err != nil {
		return err
	}

	remoteRepo = &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	repo = notreg.NewRepositoryWithOptions(remoteRepo, repositoryOpts)

	configs := map[string]string{}

	verifyOpts := notation.VerifyOptions{
		ArtifactReference:    ref.String(),
		PluginConfig:         configs,
		MaxSignatureAttempts: math.MaxInt64,
	}

	_, outcomes, err := notation.Verify(ctx, newVerifier, repo, verifyOpts)
	if err != nil || len(outcomes) == 0 {
		return ErrSignatureVerification
	}

	return nil
}

func ListNotarySignatures(reference string, tdir string) ([]godigest.Digest, error) {
	signatures := []godigest.Digest{}

	ctx := context.TODO()

	// getSignatureRepository
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return signatures, err
	}

	plainHTTP := true

	// getRepositoryClient
	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			return auth.EmptyCredential, nil
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("notation/zot_tests")

	remoteRepo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}

	sigRepo := notreg.NewRepository(remoteRepo)

	artifactDesc, err := sigRepo.Resolve(ctx, reference)
	if err != nil {
		return signatures, err
	}

	err = sigRepo.ListSignatures(ctx, artifactDesc, func(signatureManifests []ispec.Descriptor) error {
		for _, sigManifestDesc := range signatureManifests {
			signatures = append(signatures, sigManifestDesc.Digest)
		}

		return nil
	})

	return signatures, err
}

func LoadNotationSigningkeys(tdir string) (*notconfig.SigningKeys, error) {
	var err error

	var signingKeysInfo *notconfig.SigningKeys

	filePath := path.Join(tdir, "notation/signingkeys.json")

	file, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// create file
			newSigningKeys := notconfig.NewSigningKeys()

			newFile, err := os.Create(filePath)
			if err != nil {
				return newSigningKeys, err
			}

			defer newFile.Close()

			encoder := json.NewEncoder(newFile)
			encoder.SetIndent("", "    ")

			err = encoder.Encode(newSigningKeys)

			return newSigningKeys, err
		}

		return nil, err
	}

	defer file.Close()

	err = json.NewDecoder(file).Decode(&signingKeysInfo)

	return signingKeysInfo, err
}

func LoadNotationConfig(tdir string) (*notconfig.Config, error) {
	var configInfo *notconfig.Config

	filePath := path.Join(tdir, "notation/signingkeys.json")

	file, err := os.Open(filePath)
	if err != nil {
		return configInfo, err
	}

	defer file.Close()

	err = json.NewDecoder(file).Decode(&configInfo)
	if err != nil {
		return configInfo, err
	}

	// set default value
	configInfo.SignatureFormat = strings.ToLower(configInfo.SignatureFormat)
	if configInfo.SignatureFormat == "" {
		configInfo.SignatureFormat = "jws"
	}

	return configInfo, nil
}

func WriteFileWithPermission(path string, data []byte, perm fs.FileMode, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}
	flag := os.O_WRONLY | os.O_CREATE

	if overwrite {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_EXCL
	}

	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()

		return err
	}

	return file.Close()
}

func IsDigestReference(ref string) bool {
	parts := strings.SplitN(ref, "/", 2) //nolint:gomnd
	if len(parts) == 1 {
		return false
	}

	index := strings.Index(parts[1], "@")

	return index != -1
}

type isser interface {
	Is(string) bool
}

// Index returns the index of the first occurrence of name in s,
// or -1 if not present.
func Index[E isser](s []E, name string) int {
	for i, v := range s {
		if v.Is(name) {
			return i
		}
	}

	return -1
}

// Contains reports whether name is present in s.
func Contains[E isser](s []E, name string) bool {
	return Index(s, name) >= 0
}

func SignImageUsingCosign(repoTag, port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "cosign")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
	if err != nil {
		return err
	}

	imageURL := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	const timeoutPeriod = 5

	// sign the image
	return sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: timeoutPeriod * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.SignOptions{
			Registry:          options.RegistryOptions{AllowInsecure: true},
			AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=1.0"}},
			Upload:            true,
		},
		[]string{imageURL})
}

func SignImageUsingNotary(repoTag, port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "notation")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	NotationPathLock.Lock()
	defer NotationPathLock.Unlock()

	LoadNotationPath(tdir)

	// generate a keypair
	err = GenerateNotationCerts(tdir, "notation-sign-test")
	if err != nil {
		return err
	}

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s", port, repoTag)

	err = SignWithNotation("notation-sign-test", image, tdir)

	return err
}

func GetIndexBlobWithManifests(manifestDigests []godigest.Digest) ([]byte, error) {
	manifests := make([]ispec.Descriptor, 0, len(manifestDigests))

	for _, manifestDigest := range manifestDigests {
		manifests = append(manifests, ispec.Descriptor{
			Digest:    manifestDigest,
			MediaType: ispec.MediaTypeImageManifest,
		})
	}

	indexContent := ispec.Index{
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: manifests,
	}

	return json.Marshal(indexContent)
}

func MockOIDCRun() (*mockoidc.MockOIDC, error) {
	// Create a fresh RSA Private Key for token signing
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048) //nolint: gomnd

	// Create an unstarted MockOIDC server
	mockServer, _ := mockoidc.NewServer(rsaKey)

	// Create the net.Listener, kernel will chose a valid port
	listener, _ := net.Listen("tcp", "127.0.0.1:0")

	bearerMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
			// stateVal := req.Form.Get("state")
			header := req.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2) //nolint: gomnd
			if header != "" {
				if strings.ToLower(parts[0]) == "bearer" {
					req.Header.Set("Authorization", strings.Join([]string{"Bearer", parts[1]}, " "))
				}
			}

			next.ServeHTTP(response, req)
		})
	}

	err := mockServer.AddMiddleware(bearerMiddleware)
	if err != nil {
		return mockServer, err
	}
	// tlsConfig can be nil if you want HTTP
	return mockServer, mockServer.Start(listener, nil)
}

func CustomRedirectPolicy(noOfRedirect int) resty.RedirectPolicy {
	return resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if len(via) >= noOfRedirect {
			return fmt.Errorf("stopped after %d redirects", noOfRedirect) //nolint: goerr113
		}

		for key, val := range via[len(via)-1].Header {
			req.Header[key] = val
		}

		respCookies := req.Response.Cookies()
		for _, cookie := range respCookies {
			req.AddCookie(cookie)
		}

		return nil
	})
}

func GetDefaultImageStore(rootDir string, log zLog.Logger) stypes.ImageStore {
	return local.NewImageStore(rootDir, false, false, time.Hour, time.Hour, false, false, log,
		monitoring.NewMetricsServer(false, log),
		mocks.MockedLint{
			LintFn: func(repo string, manifestDigest godigest.Digest, imageStore stypes.ImageStore) (bool, error) {
				return true, nil
			},
		},
		mocks.CacheMock{},
	)
}

func GetDefaultStoreController(rootDir string, log zLog.Logger) storage.StoreController {
	return storage.StoreController{
		DefaultStore: GetDefaultImageStore(rootDir, log),
	}
}

func RemoveLocalStorageContents(imageStore stypes.ImageStore) error {
	repos, err := imageStore.GetRepositories()
	if err != nil {
		return err
	}

	for _, repo := range repos {
		// take just the first path
		err = os.RemoveAll(filepath.Join(imageStore.RootDir(), filepath.SplitList(repo)[0]))
		if err != nil {
			return err
		}
	}

	return nil
}
