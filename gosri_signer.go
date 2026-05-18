package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	dsNamespace    = "http://www.w3.org/2000/09/xmldsig#"
	xadesNamespace = "http://uri.etsi.org/01903/v1.3.2#"
)

type certEntry struct {
	cert       *x509.Certificate
	localKeyId string
	issuer     string
	cn         string
}

type keyEntry struct {
	key        crypto.Signer
	localKeyId string
}

// getIssuerString formatea el nombre del emisor en el orden exacto y sin espacios que exige el SRI.
func getIssuerString(cert *x509.Certificate) string {
	var parts []string
	// El orden estándar en Ecuador suele ser CN, L, OU, O, C
	if cert.Issuer.CommonName != "" {
		parts = append(parts, "CN="+cert.Issuer.CommonName)
	}
	for _, l := range cert.Issuer.Locality {
		parts = append(parts, "L="+l)
	}
	for _, ou := range cert.Issuer.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, o := range cert.Issuer.Organization {
		parts = append(parts, "O="+o)
	}
	for _, c := range cert.Issuer.Country {
		parts = append(parts, "C="+c)
	}
	return strings.Join(parts, ",")
}

// flattenXML elimina espacios y saltos de línea entre etiquetas para evitar que
// el DigestValue del documento cambie al ser procesado por el SRI.
func flattenXML(xmlData []byte) []byte {
	re := regexp.MustCompile(`>\s+<`)
	flat := re.ReplaceAllString(string(xmlData), "><")
	return []byte(strings.TrimSpace(flat))
}

// FirmarXML firma el XML con un certificado P12 del SRI del Ecuador.
// Selecciona el certificado de Persona Natural con serial más alto y la clave
// privada asociada mediante localKeyId.
func FirmarXML(xmlData []byte, p12Path string, password string) ([]byte, error) {
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el archivo P12: %w", err)
	}

	privateKey, signingCert, err := parseP12Certificate(p12Data, password)
	if err != nil {
		return nil, err
	}

	// Aplanamos el XML antes de procesarlo para asegurar integridad de los hashes
	flatXML := flattenXML(xmlData)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(flatXML); err != nil {
		return nil, fmt.Errorf("error leyendo XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, errors.New("XML inválido: no se encontró el elemento raíz")
	}

	if root.SelectAttrValue("id", "") == "" {
		return nil, errors.New("el XML debe contener el atributo id=\"comprobante\" en el elemento raíz")
	}

	removeExistingSignature(root)

	canonicalizer := dsig.MakeC14N10RecCanonicalizer()

	documentDigest, err := digestElement(root, canonicalizer)
	if err != nil {
		return nil, fmt.Errorf("error calculando digest del documento: %w", err)
	}

	signatureID := fmt.Sprintf("Signature-%d", time.Now().UnixNano())
	documentRefID := fmt.Sprintf("DocumentRef-%s", signatureID)
	signedPropertiesID := fmt.Sprintf("SignedProperties-%s", signatureID)
	certificateRefID := fmt.Sprintf("Certificate-%s", signatureID)

	qualifyingProperties := buildSignedProperties(signingCert, signatureID, signedPropertiesID, documentRefID)
	// IMPORTANTE: SRI referencia y valida el Digest de SignedProperties, no de QualifyingProperties
	signedPropertiesNode := qualifyingProperties.FindElement("SignedProperties")
	signedPropertiesNode.CreateAttr("xmlns:xades", xadesNamespace) // Inyectar namespace para hashing correcto
	signedPropertiesNode.CreateAttr("xmlns:ds", dsNamespace)       // Inyectar namespace ds para que la canonicalización incluya el prefijo
	signedPropertiesDigest, err := digestElement(signedPropertiesNode, canonicalizer)
	if err != nil {
		return nil, fmt.Errorf("error calculando digest de SignedProperties: %w", err)
	}

	keyInfo := buildKeyInfo(signingCert)
	keyInfo.CreateAttr("Id", certificateRefID)
	keyInfo.CreateAttr("xmlns:ds", dsNamespace) // Inyectar namespace ds para asegurar hash correcto de referencias internas
	keyInfoDigest, err := digestElement(keyInfo, canonicalizer)
	if err != nil {
		return nil, fmt.Errorf("error calculando digest de KeyInfo: %w", err)
	}

	signedInfo := buildSignedInfo(documentDigest, signedPropertiesDigest, keyInfoDigest, signatureID, documentRefID, signedPropertiesID, certificateRefID)
	signedInfo.CreateAttr("xmlns:ds", dsNamespace)

	signedInfoBytes, err := canonicalizer.Canonicalize(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("error canonicalizando SignedInfo: %w", err)
	}

	signedInfoHash := sha1.Sum(signedInfoBytes)
	signatureValue, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, signedInfoHash[:])
	if err != nil {
		return nil, fmt.Errorf("error firmando SignedInfo: %w", err)
	}

	signature := &etree.Element{Tag: "Signature", Space: "ds"}
	signature.CreateAttr("xmlns:ds", dsNamespace)
	signature.CreateAttr("Id", signatureID)
	signature.AddChild(signedInfo)

	signatureValueElement := &etree.Element{Tag: "SignatureValue", Space: "ds"}
	signatureValueElement.CreateAttr("Id", fmt.Sprintf("SignatureValue-%s", signatureID))
	signatureValueElement.SetText(base64.StdEncoding.EncodeToString(signatureValue))
	signature.AddChild(signatureValueElement)

	signature.AddChild(keyInfo)

	object := buildSignatureObject(signatureID, qualifyingProperties)
	signature.AddChild(object)

	root.AddChild(signature)

	signedXML, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("error escribiendo XML firmado: %w", err)
	}

	return signedXML, nil
}

func parseP12Certificate(p12Data []byte, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	blocks, err := pkcs12.ToPEM(p12Data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("error decodificando P12: %w", err)
	}

	var certs []certEntry
	var keys []keyEntry

	for _, block := range blocks {
		localKeyId := strings.ToLower(strings.TrimSpace(block.Headers["localKeyId"]))

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("error parseando certificado en P12: %w", err)
			}
			certs = append(certs, certEntry{
				cert:       cert,
				localKeyId: localKeyId,
				issuer:     cert.Issuer.String(),
				cn:         cert.Subject.CommonName,
			})
		case "PRIVATE KEY", "RSA PRIVATE KEY":
			privateKey, err := parsePrivateKeyPem(block)
			if err != nil {
				return nil, nil, fmt.Errorf("error parseando clave privada en P12: %w", err)
			}
			keys = append(keys, keyEntry{key: privateKey, localKeyId: localKeyId})
		}
	}

	if len(certs) == 0 {
		return nil, nil, errors.New("no se encontró ningún certificado en el P12")
	}

	selected, err := selectSigningCertificate(certs)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := selectPrivateKey(keys, selected)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, selected.cert, nil
}

func parsePrivateKeyPem(block *pem.Block) (*rsa.PrivateKey, error) {
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// Intentar primero como PKCS#8 (formato estándar moderno)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("la clave privada encontrada en el P12 no es de tipo RSA")
	}

	// Si falla, intentar como PKCS#1 como respaldo (muy común en certificados de Ecuador)
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}

	return nil, errors.New("formato de clave privada no reconocido (se requiere PKCS#1 o PKCS#8)")
}

func selectSigningCertificate(certs []certEntry) (*certEntry, error) {
	var selected *certEntry

	for i := range certs {
		cert := &certs[i]
		upperCN := strings.ToUpper(cert.cn)
		if cert.cert.IsCA || strings.Contains(upperCN, "AUTORIDAD") || strings.Contains(upperCN, "AC ") {
			continue
		}

		if selected == nil || cert.cert.SerialNumber.Cmp(selected.cert.SerialNumber) > 0 {
			selected = cert
		}
	}

	if selected == nil {
		return nil, errors.New("no se encontró certificado de firma digital de Persona Natural en el P12")
	}

	return selected, nil
}

func selectPrivateKey(keys []keyEntry, cert *certEntry) (*rsa.PrivateKey, error) {
	if cert.localKeyId != "" {
		for _, key := range keys {
			if key.localKeyId != "" && strings.EqualFold(key.localKeyId, cert.localKeyId) {
				rsaKey, ok := key.key.(*rsa.PrivateKey)
				if ok {
					return rsaKey, nil
				}
				return nil, errors.New("la clave asociada al certificado no es RSA")
			}
		}
	}

	// Fallback: buscar la clave cuyo public key coincide con el certificado.
	for _, key := range keys {
		if rsaKey, ok := key.key.(*rsa.PrivateKey); ok {
			if pubKeysEqual(&rsaKey.PublicKey, cert.cert.PublicKey) {
				return rsaKey, nil
			}
		}
	}

	if len(keys) == 1 {
		if rsaKey, ok := keys[0].key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}

	return nil, errors.New("no se encontró clave privada asociada al certificado de firma digital")
}

func pubKeysEqual(a, b crypto.PublicKey) bool {
	rsaA, okA := a.(*rsa.PublicKey)
	rsaB, okB := b.(*rsa.PublicKey)
	if okA && okB {
		return rsaA.E == rsaB.E && rsaA.N.Cmp(rsaB.N) == 0
	}
	return false
}

func removeExistingSignature(root *etree.Element) {
	for i := len(root.Child) - 1; i >= 0; i-- {
		if child, ok := root.Child[i].(*etree.Element); ok && child.Tag == "Signature" && child.Space == "ds" {
			root.RemoveChild(child)
		}
	}
}

func digestElement(el *etree.Element, canonicalizer dsig.Canonicalizer) ([]byte, error) {
	canonical, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	hash := sha1.Sum(canonical)
	return hash[:], nil
}

func buildSignedInfo(documentDigest, signedPropertiesDigest, keyInfoDigest []byte, signatureID, documentRefID, signedPropertiesID, certificateRefID string) *etree.Element {
	signedInfo := &etree.Element{Tag: "SignedInfo", Space: "ds"}
	signedInfo.CreateAttr("Id", fmt.Sprintf("SignedInfo-%s", signatureID))

	canonicalizationMethod := signedInfo.CreateElement("CanonicalizationMethod")
	canonicalizationMethod.Space = "ds"
	canonicalizationMethod.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

	signatureMethod := signedInfo.CreateElement("SignatureMethod")
	signatureMethod.Space = "ds"
	signatureMethod.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

	referenceDoc := signedInfo.CreateElement("Reference")
	referenceDoc.Space = "ds"
	referenceDoc.CreateAttr("Id", documentRefID)
	referenceDoc.CreateAttr("URI", "#comprobante")

	transforms := referenceDoc.CreateElement("Transforms")
	transforms.Space = "ds"

	transform := transforms.CreateElement("Transform")
	transform.Space = "ds"
	transform.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")

	digestMethod := referenceDoc.CreateElement("DigestMethod")
	digestMethod.Space = "ds"
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")

	digestValue := referenceDoc.CreateElement("DigestValue")
	digestValue.Space = "ds"
	digestValue.SetText(base64.StdEncoding.EncodeToString(documentDigest))

	referenceProps := signedInfo.CreateElement("Reference")
	referenceProps.Space = "ds"
	referenceProps.CreateAttr("Id", fmt.Sprintf("SignedPropertiesRef-%s", signatureID))
	referenceProps.CreateAttr("Type", "http://uri.etsi.org/01903#SignedProperties")
	referenceProps.CreateAttr("URI", "#"+signedPropertiesID)

	digestMethod2 := referenceProps.CreateElement("DigestMethod")
	digestMethod2.Space = "ds"
	digestMethod2.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")

	digestValue2 := referenceProps.CreateElement("DigestValue")
	digestValue2.Space = "ds"
	digestValue2.SetText(base64.StdEncoding.EncodeToString(signedPropertiesDigest))

	referenceCert := signedInfo.CreateElement("Reference")
	referenceCert.Space = "ds"
	referenceCert.CreateAttr("Id", fmt.Sprintf("CertificateRef-%s", signatureID))
	referenceCert.CreateAttr("URI", "#"+certificateRefID)

	digestMethod3 := referenceCert.CreateElement("DigestMethod")
	digestMethod3.Space = "ds"
	digestMethod3.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")

	digestValue3 := referenceCert.CreateElement("DigestValue")
	digestValue3.Space = "ds"
	digestValue3.SetText(base64.StdEncoding.EncodeToString(keyInfoDigest))

	return signedInfo
}

func buildKeyInfo(cert *x509.Certificate) *etree.Element {
	keyInfo := &etree.Element{Tag: "KeyInfo", Space: "ds"}

	x509Data := keyInfo.CreateElement("X509Data")
	x509Data.Space = "ds"

	x509Certificate := x509Data.CreateElement("X509Certificate")
	x509Certificate.Space = "ds"
	x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert.Raw))

	// Solo añadimos KeyValue si la clave es RSA (requerido por SRI)
	if rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keyValue := keyInfo.CreateElement("KeyValue")
		keyValue.Space = "ds"

		rsaKeyValue := keyValue.CreateElement("RSAKeyValue")
		rsaKeyValue.Space = "ds"

		modulus := rsaKeyValue.CreateElement("Modulus")
		modulus.Space = "ds"
		modulus.SetText(base64.StdEncoding.EncodeToString(rsaPubKey.N.Bytes()))

		exponent := rsaKeyValue.CreateElement("Exponent")
		exponent.Space = "ds"
		exponent.SetText(base64.StdEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes()))
	}

	return keyInfo
}

func buildSignedProperties(cert *x509.Certificate, signatureID, signedPropertiesID, documentRefID string) *etree.Element {
	qualifyingProperties := &etree.Element{Tag: "QualifyingProperties", Space: "xades"}
	qualifyingProperties.CreateAttr("Target", fmt.Sprintf("#%s", signatureID))
	qualifyingProperties.CreateAttr("xmlns:xades", xadesNamespace)

	signedProperties := qualifyingProperties.CreateElement("SignedProperties")
	signedProperties.Space = "xades"
	signedProperties.CreateAttr("Id", signedPropertiesID)

	signedSignatureProperties := signedProperties.CreateElement("SignedSignatureProperties")
	signedSignatureProperties.Space = "xades"

	signingTime := signedSignatureProperties.CreateElement("SigningTime")
	signingTime.Space = "xades"
	signingTime.SetText(time.Now().Format("2006-01-02T15:04:05.000-07:00"))

	signingCertificate := signedSignatureProperties.CreateElement("SigningCertificate")
	signingCertificate.Space = "xades"

	certElement := signingCertificate.CreateElement("Cert")
	certElement.Space = "xades"

	certDigest := certElement.CreateElement("CertDigest")
	certDigest.Space = "xades"

	digestMethod := certDigest.CreateElement("DigestMethod")
	digestMethod.Space = "ds"
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")

	digestValue := certDigest.CreateElement("DigestValue")
	digestValue.Space = "ds"
	certHash := sha1.Sum(cert.Raw)
	digestValue.SetText(base64.StdEncoding.EncodeToString(certHash[:]))

	issuerSerial := certElement.CreateElement("IssuerSerial")
	issuerSerial.Space = "xades"

	x509IssuerName := issuerSerial.CreateElement("X509IssuerName")
	x509IssuerName.Space = "ds"
	x509IssuerName.SetText(getIssuerString(cert)) // Usar helper para formato exacto

	x509SerialNumber := issuerSerial.CreateElement("X509SerialNumber")
	x509SerialNumber.Space = "ds"
	x509SerialNumber.SetText(cert.SerialNumber.String())

	signedDataObjectProperties := signedProperties.CreateElement("SignedDataObjectProperties")
	signedDataObjectProperties.Space = "xades"

	dataObjectFormat := signedDataObjectProperties.CreateElement("DataObjectFormat")
	dataObjectFormat.Space = "xades"
	dataObjectFormat.CreateAttr("ObjectReference", fmt.Sprintf("#%s", documentRefID))

	description := dataObjectFormat.CreateElement("Description")
	description.Space = "xades"
	description.SetText("Firma digital")

	mimeType := dataObjectFormat.CreateElement("MimeType")
	mimeType.Space = "xades"
	mimeType.SetText("text/xml")

	encoding := dataObjectFormat.CreateElement("Encoding")
	encoding.Space = "xades"
	encoding.SetText("UTF-8")

	return qualifyingProperties
}

func buildSignatureObject(signatureID string, signedProperties *etree.Element) *etree.Element {
	object := &etree.Element{Tag: "Object", Space: "ds"}
	object.CreateAttr("Id", fmt.Sprintf("SignatureObject-%s", signatureID))

	// We copy the signedProperties subtree into the Object body.
	qualifyingProperties := signedProperties.Copy()
	object.AddChild(qualifyingProperties)

	return object
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Uso: %s <input.xml> <cert.p12> <password>\n", os.Args[0])
		os.Exit(1)
	}

	inputPath := os.Args[1]
	p12Path := os.Args[2]
	password := os.Args[3]

	xmlData, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error leyendo XML de entrada: %v\n", err)
		os.Exit(1)
	}

	signedXML, err := FirmarXML(xmlData, p12Path, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error firmando XML: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(signedXML)
}
