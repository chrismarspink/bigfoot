{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["codeSigning"],
	"basicConstraints": { "isCA": false }
}
